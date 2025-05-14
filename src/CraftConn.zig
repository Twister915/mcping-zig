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

pub fn DecodedPkt(comptime Pkt: type) type {
    return struct {
        packet: Pkt,
        arena: *std.heap.ArenaAllocator,
        allocator: std.mem.Allocator,

        pub fn deinit(ctr: @This()) void {
            ctr.arena.deinit();
            ctr.allocator.destroy(ctr.arena);
        }
    };
}

pub const ReadPkt = struct {
    id: i32,
    // we're borrowing this memory from the connection, so that's why there's const and no deinit
    data: []const u8,

    const Self = @This();

    // if you call this, we decode the packet into owned memory (call deinit() on the returned T)
    pub fn decodeAs(self: Self, comptime T: type, allocator: std.mem.Allocator) !DecodedPkt(T) {
        const encoding = comptime defaultPacketEncoding(T);

        var arena = try allocator.create(std.heap.ArenaAllocator);
        arena.* = std.heap.ArenaAllocator.init(allocator);
        const arena_allocator = arena.allocator();

        var stream = std.io.fixedBufferStream(self.data);
        const expected_len = self.data.len;
        const decoded: CraftTypes.Decoded(T) = try CraftTypes.decode(T, stream.reader(), arena_allocator, encoding);
        if (decoded.bytes_read != expected_len) {
            return error.PacketNotCompletelyParsed;
        }
        return .{
            .packet = decoded.value,
            .arena = arena,
            .allocator = allocator,
        };
    }
};

pub fn readPacket(conn: *Conn) !ReadPkt {
    conn.clearBuffers();

    const reader = conn.reader.reader();
    const pkt_length: usize = @intCast((try CraftTypes.decode(i32, reader, conn.allocator, .varnum)).value);

    var id_and_body: []u8 = undefined;
    switch (conn.compression) {
        .enabled => |*compress| {
            const data_length_decoded = try CraftTypes.decode(i32, reader, conn.allocator, .varnum);
            const data_length: usize = @intCast(data_length_decoded.value);
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

    std.debug.print("rx: {any}\n", .{id_and_body});
    var id_body_stream = std.io.fixedBufferStream(id_and_body);
    const id_body_reader = id_body_stream.reader();
    const packet_id_decoded = try CraftTypes.decode(i32, id_body_reader, conn.allocator, .varnum);
    return .{
        .id = packet_id_decoded.value,
        .data = id_and_body[packet_id_decoded.bytes_read..],
    };
}

pub fn writePacket(conn: *Conn, id: i32, packet: anytype) !usize {
    const Packet: type = @TypeOf(packet);
    if (std.meta.hasFn(@TypeOf(packet), "deinit")) {
        defer packet.deinit();
    }

    const encoding = comptime defaultPacketEncoding(Packet);

    conn.clearBuffers();

    const body_and_id_length = try packetLength(id, packet);
    switch (conn.compression) {
        .enabled => |*comp| {
            // [length]
            // [data length] (or 0)
            // [compressed packet] (or uncompressed)
            if (body_and_id_length > comp.threshold) {
                const data_length: i32 = @intCast(body_and_id_length);
                // write the compressed data to comp.buf
                var compressor = try std.compress.zlib.compressor(comp.buf.writer(), .{});
                const compressor_writer = compressor.writer();
                _ = try CraftTypes.encode(id, compressor_writer, .varnum);
                _ = try CraftTypes.encode(packet, compressor_writer, encoding);
                try compressor.finish();

                // write the packet we actually intend to send
                const actual_size: usize = (try CraftTypes.length(data_length, .varnum)) + comp.buf.items.len;
                const conn_buf_writer = conn.buf.writer();
                _ = try CraftTypes.encode(@as(i32, @intCast(actual_size)), conn_buf_writer, .varnum);
                _ = try CraftTypes.encode(data_length, conn_buf_writer, .varnum);
                try conn.buf.appendSlice(comp.buf.items);
            } else {
                _ = try CraftTypes.encode(@as(i32, @intCast(body_and_id_length + 1)), conn.buf.writer(), .varnum);
                try conn.buf.append(0); // data length == 0
                _ = try CraftTypes.encode(id, conn.buf.writer(), .varnum);
                _ = try CraftTypes.encode(packet, conn.buf.writer(), encoding);
            }
        },
        .disabled => {
            _ = try CraftTypes.encode(@as(i32, @intCast(body_and_id_length)), conn.buf.writer(), .varnum);
            _ = try CraftTypes.encode(id, conn.buf.writer(), .varnum);
            _ = try CraftTypes.encode(packet, conn.buf.writer(), encoding);
        },
    }

    const bytes_to_send = conn.buf.items;
    try conn.socket.writeAll(bytes_to_send);
    std.debug.print("tx: {any}\n", .{bytes_to_send});
    return bytes_to_send.len;
}

pub fn packetLength(id: i32, packet: anytype) !usize {
    const packet_encoding = comptime defaultPacketEncoding(@TypeOf(packet));
    return (try CraftTypes.length(id, .varnum)) + (try CraftTypes.length(packet, packet_encoding));
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

fn defaultPacketEncoding(comptime Packet: type) CraftTypes.Encoding(Packet) {
    if (Packet == void) {
        return {};
    }

    if (@hasDecl(Packet, "ENCODING")) {
        return Packet.ENCODING;
    }

    return .{};
}
