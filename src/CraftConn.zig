const std = @import("std");
const net = std.net;
const CraftTypes = @import("CraftTypes.zig");

const BUF_SIZE = 256;
const bufReader = std.io.BufferedReader(BUF_SIZE, net.Stream.Reader);

socket: net.Stream,
reader: bufReader,
buf: std.ArrayList(u8),
compression: Compression = .disabled,
allocator: std.mem.Allocator,

const Conn = @This();

const Compression = union(enum) {
    enabled: Enabled,
    disabled,

    const Enabled = struct {
        threshold: usize,
        buf: std.ArrayList(u8),
    };
};

pub fn connect(allocator: std.mem.Allocator, address: []const u8, port: u16) !Conn {
    const stream = try net.tcpConnectToHost(allocator, address, port);
    return .{
        .socket = stream,
        .reader = .{ .unbuffered_reader = stream.reader() },
        .buf = std.ArrayList(u8).init(allocator),
        .allocator = allocator,
    };
}

pub fn deinit(conn: Conn) void {
    switch (conn.compression) {
        .enabled => |c| c.buf.deinit(),
        else => {},
    }
    conn.buf.deinit();
    conn.socket.close();
}

pub const ReadPkt = struct {
    id: CraftTypes.VarInt,
    // we're borrowing this memory from the connection, so that's why there's const and no deinit
    data: []const u8,

    const Self = @This();

    // if you call this, we decode the packet into owned memory (call deinit() on the returned T)
    pub fn decodeAs(self: Self, allocator: std.mem.Allocator, comptime T: type) !T {
        var stream = std.io.fixedBufferStream(self.data);
        const expected_len = self.data.len;
        const decoded: CraftTypes.Decoded(T) = try CraftTypes.decode(T, stream.reader(), allocator);
        if (decoded.bytes_read != expected_len) {
            return error.PacketNotCompletelyParsed;
        }
        return decoded.value;
    }
};

pub fn readPacket(conn: *Conn) !ReadPkt {
    conn.clearBuffers();

    const reader = conn.reader.reader();
    const pkt_length: usize = @intCast(@intFromEnum((try CraftTypes.decode(CraftTypes.VarInt, reader, conn.allocator)).value));

    var id_and_body: []u8 = undefined;
    switch (conn.compression) {
        .enabled => |*compress| {
            const data_length_decoded = try CraftTypes.decode(CraftTypes.VarInt, reader, conn.allocator);
            const data_length: usize = @intCast(@intFromEnum(data_length_decoded.value));
            const bytes_left = pkt_length - data_length_decoded.bytes_read;
            if (data_length == 0) {
                // packet is not compressed, just read it into the buffer
                id_and_body = try conn.buf.addManyAsSlice(bytes_left);
                try reader.readNoEof(id_and_body);
            } else {
                // packet is compressed, read it into the compression buffer
                const compressed_buf = try compress.buf.addManyAsSlice(bytes_left);
                try reader.readNoEof(compressed_buf);

                // decompress
                var compressed_stream = std.io.fixedBufferStream(compressed_buf);
                try std.compress.zlib.decompress(compressed_stream.reader(), conn.buf.writer());
                id_and_body = conn.buf.items;
                if (id_and_body.len != data_length) {
                    return error.DecompressDataLengthMismatch;
                }
            }
        },
        .disabled => {
            id_and_body = try conn.buf.addManyAsSlice(pkt_length);
            try reader.readNoEof(id_and_body);
        },
    }

    var id_body_stream = std.io.fixedBufferStream(id_and_body);
    const id_body_reader = id_body_stream.reader();
    const packet_id_decoded = try CraftTypes.decode(CraftTypes.VarInt, id_body_reader, conn.allocator);
    return .{
        .id = packet_id_decoded.value,
        .data = id_and_body[packet_id_decoded.bytes_read..],
    };
}

pub fn writePacket(conn: *Conn, id: CraftTypes.VarInt.Int, packet: anytype) !usize {
    if (std.meta.hasFn(@TypeOf(packet), "deinit")) {
        defer packet.deinit();
    }

    // clear buffers
    conn.clearBuffers();

    // create a small reserved space (5 bytes), at the start of the buffer we'll eventually write to the wire
    // to hold the "data length"
    switch (conn.compression) {
        // reserve space for length + data length in both buffers
        .enabled => |*e| {
            // this space is reserved for uncompressed packets in compressed mode
            // data length is always 0 in this case, so reserved space is packet length + 1
            _ = try conn.buf.addManyAsSlice(CraftTypes.VarInt.BYTE_SIZE + 1);

            // this space is reserved for writing the result of compressing the packet in conn.buf
            _ = try e.buf.addManyAsSlice(CraftTypes.VarInt.BYTE_SIZE * 2);
        },
        // or just reserve space for data length in uncompressed buffer
        .disabled => {
            _ = try conn.buf.addManyAsSlice(CraftTypes.VarInt.BYTE_SIZE);
        },
    }

    // encode the packet to conn.buf
    const packet_data_offset = conn.buf.items.len;
    const writer = conn.buf.writer();
    // encode the packet ID
    _ = try CraftTypes.encode(@as(CraftTypes.VarInt, @enumFromInt(id)), writer);
    // encode the packet payload
    _ = try CraftTypes.encode(packet, writer);

    const packet_data = conn.buf.items[packet_data_offset..];
    var data_length: CraftTypes.VarInt = @enumFromInt(packet_data.len);

    // all cases in the switch statement below overwrite this undefined initial state
    // !! it would be UB if any branch of the switch did not set this to something !!
    var bytes_to_send: []const u8 = undefined;

    switch (conn.compression) {
        .enabled => |*c| {
            if (packet_data.len >= c.threshold) {
                // threshold is met, so we will perform compression

                // create a reader which lets zlib read our uncompressed packet data
                var pkt_stream = std.io.fixedBufferStream(packet_data);
                // compress the data from packetData (conn.buf) to the compression buffer (c.buf)
                try std.compress.zlib.compress(pkt_stream.reader(), c.buf.writer(), .{});
                // calculate the size of the compressed packet (packet id + packet body)
                const compressed_size: usize = c.buf.items.len - (CraftTypes.VarInt.BYTE_SIZE * 2);

                // data_length = the uncompressed size of the packet
                // data_length_bytes = the number of bytes required to encode the dataLength VarInt
                const data_length_bytes = data_length.length();

                // length = the packet length (dataLength + compressed data)
                const length: CraftTypes.VarInt = @enumFromInt(compressed_size + data_length_bytes);

                // we reserved 10 bytes in c.buf earlier, which can be used for encoding length and data length
                // so now, we can create a writer which will allow us to encode to that region of memory
                var write_stream = std.io.fixedBufferStream(c.buf.items[0 .. CraftTypes.VarInt.BYTE_SIZE * 2]);
                const w = write_stream.writer();

                // encode the two numbers to that space
                var bytes_used: usize = 0;
                bytes_used += try CraftTypes.encode(length, w);
                bytes_used += try CraftTypes.encode(data_length, w);

                // shift the numbers so they start immediately before the compressed packet data
                const start_idx = (CraftTypes.VarInt.BYTE_SIZE * 2) - bytes_used;
                if (start_idx > 0) {
                    const end_idx = start_idx + bytes_used;
                    std.mem.copyBackwards(
                        u8,
                        c.buf.items[start_idx..end_idx],
                        c.buf.items[0..bytes_used],
                    );
                }

                // send everything from the start of the lengths until the end of the compressed packet data
                bytes_to_send = c.buf.items[start_idx..];
            } else {
                // no compress, even though enabled... so we won't use the compress buffer
                // instead, we will encode a data length of 0 in front of the packet in the conn.buf

                // data length is no longer the "uncompressed size" but is instead the length prefix for the entire
                // packet, similar to uncompressed mode.
                //
                // When compression is enabled, but the threshold is not met, we want to send:
                //
                // * (VarInt) length of the following bytes (data length + packet id + packet body)
                // * (VarInt) data length = 0 (exactly 1 byte)
                // * (VarInt) packet id
                // * (??????) packet body
                //
                // currently, dataLength refers to the byte size of packet id + packet body, so all we need to add
                // is the length of encoding a data length of "0" (which is 1 byte)
                data_length = @enumFromInt(@intFromEnum(data_length) + 1);

                // write this data length before the packet data
                var prefix_stream = std.io.fixedBufferStream(conn.buf.items[0..CraftTypes.VarInt.BYTE_SIZE]);
                const length_bytes = try CraftTypes.encode(data_length, prefix_stream.writer());

                // copy the VarInt forward so it starts at the right position
                const start_idx = CraftTypes.VarInt.BYTE_SIZE - length_bytes;
                if (start_idx > 0) {
                    std.mem.copyBackwards(
                        u8,
                        conn.buf.items[start_idx..CraftTypes.VarInt.BYTE_SIZE],
                        conn.buf.items[0..length_bytes],
                    );
                }

                // ensure the data length byte is set to 0
                conn.buf.items[CraftTypes.VarInt.BYTE_SIZE] = 0x00;
                bytes_to_send = conn.buf.items[start_idx..];
            }
        },
        .disabled => {
            // compression is not enabled, so let's just write the data length in front of the packet in conn.buf
            //
            // we reserved 5 bytes earlier for this purpose
            var prefix_stream = std.io.fixedBufferStream(conn.buf.items[0..CraftTypes.VarInt.BYTE_SIZE]);
            const length_bytes = try CraftTypes.encode(data_length, prefix_stream.writer());

            // shift the length so that it starts right before the packet data
            const start_idx = CraftTypes.VarInt.BYTE_SIZE - length_bytes;
            if (start_idx > 0) {
                std.mem.copyBackwards(
                    u8,
                    conn.buf.items[start_idx..CraftTypes.VarInt.BYTE_SIZE],
                    conn.buf.items[0..length_bytes],
                );
            }

            // send everything from the start of the length until the end of the packet data
            bytes_to_send = conn.buf.items[start_idx..];
        },
    }

    try conn.socket.writeAll(bytes_to_send);
    return bytes_to_send.len;
}

pub fn setCompressionThreshold(conn: *Conn, threshold: usize) !void {
    if (conn.isCompressionEnabled()) {
        return error.CompressionAlreadyEnabled;
    }

    conn.compression = .{ .enabled = .{
        .buf = std.ArrayList(u8).init(conn.allocator),
        .threshold = threshold,
    } };
}

pub fn isCompressionEnabled(conn: *Conn) bool {
    return switch (conn.compression) {
        .disabled => false,
        .enabled => true,
    };
}

fn clearBuffers(conn: *Conn) void {
    conn.buf.clearRetainingCapacity();
    switch (conn.compression) {
        .enabled => |*e| e.buf.clearRetainingCapacity(),
        .disabled => {},
    }
}
