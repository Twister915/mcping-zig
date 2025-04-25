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
        const expectedLen = self.data.len;
        const decoded: CraftTypes.Decoded(T) = try T.decode(allocator, stream.reader(), expectedLen);
        if (decoded.bytes != expectedLen) {
            return error.PacketNotCompletelyParsed;
        }
        return decoded.value;
    }
};

pub fn readPacket(conn: *Conn) !ReadPkt {
    conn.clearBuffers();

    const reader = conn.reader.reader();
    const pktLength: usize = @intCast((try CraftTypes.VarInt.decode(conn.allocator, reader, 0)).value.value);

    var idAndBody: []u8 = undefined;
    switch (conn.compression) {
        .enabled => |*compress| {
            const dataLengthDecoded = try CraftTypes.VarInt.decode(conn.allocator, reader, pktLength);
            const dataLength: usize = @intCast(dataLengthDecoded.value.value);
            const bytesLeft = pktLength - dataLengthDecoded.bytes;
            if (dataLength == 0) {
                // packet is not compressed, just read it into the buffer
                idAndBody = try conn.buf.addManyAsSlice(bytesLeft);
                try reader.readNoEof(idAndBody);
            } else {
                // packet is compressed, read it into the compression buffer
                const compressedBuf = try compress.buf.addManyAsSlice(bytesLeft);
                try reader.readNoEof(compressedBuf);

                // decompress
                var compressedStream = std.io.fixedBufferStream(compressedBuf);
                try std.compress.zlib.decompress(compressedStream.reader(), conn.buf.writer());
                idAndBody = conn.buf.items;
                if (idAndBody.len != dataLength) {
                    return error.DecompressDataLengthMismatch;
                }
            }
        },
        .disabled => {
            idAndBody = try conn.buf.addManyAsSlice(pktLength);
            try reader.readNoEof(idAndBody);
        },
    }

    var idBodyStream = std.io.fixedBufferStream(idAndBody);
    const idBodyReader = idBodyStream.reader();
    const packetIdDecoded = try CraftTypes.VarInt.decode(conn.allocator, idBodyReader, idAndBody.len);
    return .{
        .id = packetIdDecoded.value,
        .data = idAndBody[packetIdDecoded.bytes..],
    };
}

pub fn writePacket(conn: *Conn, id: CraftTypes.VarInt, packet: anytype) !usize {
    if (std.meta.hasFn(@TypeOf(packet), "deinit")) {
        defer packet.deinit();
    }

    if (!std.meta.hasFn(@TypeOf(packet), "encode")) {
        @compileError("packet type " ++ @typeName(@TypeOf(packet)) ++ " does not have encode method");
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
            _ = try conn.buf.addManyAsSlice(CraftTypes.VarInt.ByteSize + 1);

            // this space is reserved for writing the result of compressing the packet in conn.buf
            _ = try e.buf.addManyAsSlice(CraftTypes.VarInt.ByteSize * 2);
        },
        // or just reserve space for data length in uncompressed buffer
        .disabled => {
            _ = try conn.buf.addManyAsSlice(CraftTypes.VarInt.ByteSize);
        },
    }

    // encode the packet to conn.buf
    const packetDataOffset = conn.buf.items.len;
    const writer = conn.buf.writer();
    // encode the packet ID
    _ = try id.encode(writer);
    // encode the packet payload
    _ = try packet.encode(writer);

    const packetData = conn.buf.items[packetDataOffset..];
    var dataLength = CraftTypes.VarInt.init(@intCast(packetData.len));

    // all cases in the switch statement below overwrite this undefined initial state
    // !! it would be UB if any branch of the switch did not set this to something !!
    var bytesToSend: []const u8 = undefined;

    switch (conn.compression) {
        .enabled => |*c| {
            if (packetData.len >= c.threshold) {
                // threshold is met, so we will perform compression

                // create a reader which lets zlib read our uncompressed packet data
                var pktStream = std.io.fixedBufferStream(packetData);
                // compress the data from packetData (conn.buf) to the compression buffer (c.buf)
                try std.compress.zlib.compress(pktStream.reader(), c.buf.writer(), .{});
                // calculate the size of the compressed packet (packet id + packet body)
                const compressedSize: usize = c.buf.items.len - (CraftTypes.VarInt.ByteSize * 2);

                // dataLength = the uncompressed size of the packet
                // dataLengthBytes = the number of bytes required to encode the dataLength VarInt
                const dataLengthBytes = dataLength.length();

                // length = the packet length (dataLength + compressed data)
                const length = CraftTypes.VarInt.init(@intCast(compressedSize + dataLengthBytes));

                // we reserved 10 bytes in c.buf earlier, which can be used for encoding length and data length
                // so now, we can create a writer which will allow us to encode to that region of memory
                var writeStream = std.io.fixedBufferStream(c.buf.items[0 .. CraftTypes.VarInt.ByteSize * 2]);
                const w = writeStream.writer();

                // encode the two numbers to that space
                var bytesUsed: usize = 0;
                bytesUsed += try length.encode(w);
                bytesUsed += try dataLength.encode(w);

                // shift the numbers so they start immediately before the compressed packet data
                const startIdx = (CraftTypes.VarInt.ByteSize * 2) - bytesUsed;
                if (startIdx > 0) {
                    const endIdx = startIdx + bytesUsed;
                    std.mem.copyBackwards(
                        u8,
                        c.buf.items[startIdx..endIdx],
                        c.buf.items[0..bytesUsed],
                    );
                }

                // send everything from the start of the lengths until the end of the compressed packet data
                bytesToSend = c.buf.items[startIdx..];
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
                dataLength.value += 1;

                // write this data length before the packet data
                var prefixStream = std.io.fixedBufferStream(conn.buf.items[0..CraftTypes.VarInt.ByteSize]);
                const lBytes = try dataLength.encode(prefixStream.writer());

                // copy the VarInt forward so it starts at the right position
                const startIdx = CraftTypes.VarInt.ByteSize - lBytes;
                if (startIdx > 0) {
                    std.mem.copyBackwards(
                        u8,
                        conn.buf.items[startIdx..CraftTypes.VarInt.ByteSize],
                        conn.buf.items[0..lBytes],
                    );
                }

                // ensure the data length byte is set to 0
                conn.buf.items[CraftTypes.VarInt.ByteSize] = 0x00;
                bytesToSend = conn.buf.items[startIdx..];
            }
        },
        .disabled => {
            // compression is not enabled, so let's just write the data length in front of the packet in conn.buf
            //
            // we reserved 5 bytes earlier for this purpose
            var prefixStream = std.io.fixedBufferStream(conn.buf.items[0..CraftTypes.VarInt.ByteSize]);
            const lBytes = try dataLength.encode(prefixStream.writer());

            // shift the length so that it starts right before the packet data
            const startIdx = CraftTypes.VarInt.ByteSize - lBytes;
            if (startIdx > 0) {
                std.mem.copyBackwards(
                    u8,
                    conn.buf.items[startIdx..CraftTypes.VarInt.ByteSize],
                    conn.buf.items[0..lBytes],
                );
            }

            // send everything from the start of the length until the end of the packet data
            bytesToSend = conn.buf.items[startIdx..];
        },
    }

    try conn.socket.writeAll(bytesToSend);
    return bytesToSend.len;
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
