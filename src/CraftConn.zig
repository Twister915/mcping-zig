const std = @import("std");
const net = std.net;
const craft_io = @import("io.zig");

const BUF_SIZE = 256;
const bufReader = std.io.BufferedReader(BUF_SIZE, net.Stream.Reader);

socket: net.Stream,
address: []const u8,
port: u16,
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
        .address = try allocator.dupe(u8, address),
        .port = port,
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
    conn.allocator.free(conn.address);
}

pub const ReadPkt = struct {
    id: i32,
    // we're borrowing this memory from the connection, so that's why there's const and no deinit
    data: []const u8,

    const Self = @This();

    // if you call this, we decode the packet into owned memory (call deinit() on the returned T)
    pub fn decodeAs(self: Self, comptime T: type, arena_allocator: *std.heap.ArenaAllocator) !T {
        const encoding = comptime defaultPacketEncoding(T);
        var stream = std.io.fixedBufferStream(self.data);
        const decoded: craft_io.Decoded(T) = try craft_io.decode(
            T,
            stream.reader(),
            arena_allocator,
            encoding,
        );
        const expected_len = self.data.len;
        if (decoded.bytes_read != expected_len) {
            return error.PacketNotCompletelyParsed;
        }
        return decoded.value;
    }

    pub fn decodeWithoutArena(self: Self, comptime T: type, allocator: std.mem.Allocator) !OwnedPacket(T) {
        const arena_allocator = try allocator.create(std.heap.ArenaAllocator);
        arena_allocator.* = .init(allocator);

        const packet = try self.decodeAs(T, arena_allocator);
        return .{ .packet = packet, .arena = arena_allocator };
    }
};

pub fn OwnedPacket(comptime Payload: type) type {
    return struct {
        packet: Payload,
        arena: *std.heap.ArenaAllocator,

        pub fn deinit(self: @This()) void {
            self.arena.deinit();
        }
    };
}

pub fn readAndExpectPacket(conn: *Conn, expected_id: i32, comptime Packet: type, arena_allocator: *std.heap.ArenaAllocator) !Packet {
    const next_packet = try conn.readPacket();
    if (next_packet.id != expected_id) {
        return error.UnexpectedPacket;
    }

    return try next_packet.decodeAs(Packet, arena_allocator);
}

pub fn readPacket(conn: *Conn) !ReadPkt {
    conn.clearBuffers();

    const reader = conn.reader.reader();
    const pkt_length: usize = @intCast((try craft_io.decodeInt(i32, reader, .varnum)).value);

    var id_and_body: []u8 = undefined;
    switch (conn.compression) {
        .enabled => |*compress| {
            const data_length_decoded = try craft_io.decodeInt(i32, reader, .varnum);
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

    var id_body_stream = std.io.fixedBufferStream(id_and_body);
    const id_body_reader = id_body_stream.reader();
    const packet_id_decoded = try craft_io.decodeInt(i32, id_body_reader, .varnum);
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

    const body_and_id_length = try packetLength(id, packet, conn.allocator);
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
                _ = try craft_io.encode(id, compressor_writer, conn.allocator, .varnum);
                _ = try craft_io.encode(packet, compressor_writer, conn.allocator, encoding);
                try compressor.finish();

                // write the packet we actually intend to send
                const actual_size: usize = (try craft_io.length(data_length, conn.allocator, .varnum)) + comp.buf.items.len;
                const conn_buf_writer = conn.buf.writer();
                _ = try craft_io.encode(@as(i32, @intCast(actual_size)), conn_buf_writer, conn.allocator, .varnum);
                _ = try craft_io.encode(data_length, conn_buf_writer, conn.allocator, .varnum);
                try conn.buf.appendSlice(comp.buf.items);
            } else {
                _ = try craft_io.encode(@as(i32, @intCast(body_and_id_length + 1)), conn.buf.writer(), conn.allocator, .varnum);
                try conn.buf.append(0); // data length == 0
                _ = try craft_io.encode(id, conn.buf.writer(), conn.allocator, .varnum);
                _ = try craft_io.encode(packet, conn.buf.writer(), conn.allocator, encoding);
            }
        },
        .disabled => {
            _ = try craft_io.encode(@as(i32, @intCast(body_and_id_length)), conn.buf.writer(), conn.allocator, .varnum);
            _ = try craft_io.encode(id, conn.buf.writer(), conn.allocator, .varnum);
            _ = try craft_io.encode(packet, conn.buf.writer(), conn.allocator, encoding);
        },
    }

    const bytes_to_send = conn.buf.items;
    try conn.socket.writeAll(bytes_to_send);
    return bytes_to_send.len;
}

pub fn packetLength(id: i32, packet: anytype, allocator: std.mem.Allocator) !usize {
    const packet_encoding = comptime defaultPacketEncoding(@TypeOf(packet));
    const id_len = try craft_io.lengthInt(id, .varnum);
    const payload_len = try craft_io.length(packet, allocator, packet_encoding);
    return id_len + payload_len;
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

fn defaultPacketEncoding(comptime Packet: type) craft_io.Encoding(Packet) {
    if (Packet == void) {
        return {};
    }

    if (@hasDecl(Packet, "ENCODING")) {
        return Packet.ENCODING;
    }

    return .{};
}
