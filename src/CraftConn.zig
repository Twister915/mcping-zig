const std = @import("std");
const net = std.net;
const craft_io = @import("io.zig");
const cfb8 = @import("cfb8.zig");

const BUF_SIZE = 256;
const bufReader = std.io.BufferedReader(BUF_SIZE, net.Stream.Reader);

const log = std.log.scoped(.craft_conn);

socket: net.Stream,
address: []const u8,
port: u16,
reader: bufReader,
buf: std.ArrayList(u8),
compression: ?Compression = null,
encryption: ?Encryption = null,
allocator: std.mem.Allocator,

const Conn = @This();

const Compression = struct {
    threshold: usize,
    buf: std.ArrayList(u8),
};

const Encryption = struct {
    rx: cfb8.Cipher,
    tx: cfb8.Cipher,
};

pub fn connect(allocator: std.mem.Allocator, address: []const u8, port: u16) !Conn {
    log.debug("establishing connection to target {s}:{d}", .{ address, port });
    const stream = try net.tcpConnectToHost(allocator, address, port);
    log.debug("connected to target {s}:{d}", .{ address, port });
    return .{
        .socket = stream,
        .address = try allocator.dupe(u8, address),
        .port = port,
        .reader = .{ .unbuffered_reader = stream.reader() },
        .buf = std.ArrayList(u8).init(allocator),
        .allocator = allocator,
    };
}

pub fn deinit(conn: *Conn) void {
    if (conn.compression) |*compression| {
        compression.buf.deinit();
    }

    conn.buf.deinit();
    conn.socket.close();
    log.debug("{*} connection shutdown", .{conn});
    conn.allocator.free(conn.address);
}

pub const ReadPkt = struct {
    id: i32,
    // we're borrowing this memory from the connection, so that's why there's const and no deinit
    payload: []const u8,

    const Self = @This();

    // if you call this, we decode the packet into owned memory (call deinit() on the returned T)
    pub fn decodeAs(self: Self, comptime T: type, arena_allocator: *std.heap.ArenaAllocator) !T {
        const encoding = comptime defaultPacketEncoding(T);
        var stream = std.io.fixedBufferStream(self.payload);
        const decoded: craft_io.Decoded(T) = try craft_io.decode(
            T,
            stream.reader(),
            arena_allocator,
            encoding,
        );
        const expected_len = self.payload.len;
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
    const conn_reader = conn.reader.reader();
    if (conn.encryption) |*encryption| {
        return conn.readPacketFrom(encryption.rx.reader(conn_reader));
    } else {
        return conn.readPacketFrom(conn_reader);
    }
}

fn readPacketFrom(conn: *Conn, reader: anytype) !ReadPkt {
    conn.clearBuffers();

    const pkt_length_decoded = try craft_io.decodeInt(i32, reader, .varnum);
    var bytes_read = pkt_length_decoded.bytes_read;
    var bytes_decoded = bytes_read;
    const pkt_length: usize = @intCast(pkt_length_decoded.value);

    var id_and_payload: []u8 = undefined;
    if (conn.compression) |*compress| {
        const data_length_decoded = try craft_io.decodeInt(i32, reader, .varnum);
        bytes_read += data_length_decoded.bytes_read;
        bytes_decoded += data_length_decoded.bytes_read;
        const data_length: usize = @intCast(data_length_decoded.value);
        const bytes_left = pkt_length - data_length_decoded.bytes_read;
        if (data_length == 0) {
            // packet is not compressed, just read it into the buffer
            id_and_payload = try conn.buf.addManyAsSlice(bytes_left);
            try reader.readNoEof(id_and_payload);
            bytes_read += bytes_left;
            bytes_decoded += bytes_left;
        } else {
            // packet is compressed, read it into the compression buffer
            const compressed_buf = try compress.buf.addManyAsSlice(bytes_left);
            try reader.readNoEof(compressed_buf);
            bytes_read += bytes_left;

            // decompress
            var compressed_stream = std.io.fixedBufferStream(compressed_buf);
            try std.compress.zlib.decompress(compressed_stream.reader(), conn.buf.writer());
            bytes_decoded += conn.buf.items.len;
            id_and_payload = conn.buf.items;
            if (id_and_payload.len != data_length) {
                return error.DecompressDataLengthMismatch;
            }
        }
    } else {
        id_and_payload = try conn.buf.addManyAsSlice(pkt_length);
        try reader.readNoEof(id_and_payload);
        bytes_read += pkt_length;
        bytes_decoded += pkt_length;
    }

    var id_payload_stream = std.io.fixedBufferStream(id_and_payload);
    const id_decoded = try craft_io.decodeInt(i32, id_payload_stream.reader(), .varnum);
    const id = id_decoded.value;
    const payload = id_and_payload[id_decoded.bytes_read..]; // skip the bytes for the ID

    log.debug(
        "{*} [rx]: id={x}, bytes_read={d}, bytes_decoded={d}, payload_bytes={d}",
        .{
            conn,
            id,
            bytes_read,
            bytes_decoded,
            payload.len,
        },
    );

    return .{ .id = id, .payload = payload };
}

pub fn writePacket(conn: *Conn, id: i32, packet: anytype) !usize {
    return conn.writePacketWithEncoding(
        id,
        packet,
        comptime defaultPacketEncoding(@TypeOf(packet)),
    );
}

pub fn writePacketWithEncoding(
    conn: *Conn,
    id: i32,
    packet: anytype,
    comptime encoding: craft_io.Encoding(@TypeOf(packet)),
) !usize {
    conn.clearBuffers();

    var arena_allocator = std.heap.ArenaAllocator.init(conn.allocator);
    defer arena_allocator.deinit();
    const allocator = arena_allocator.allocator();

    const payload_length = try craft_io.length(packet, allocator, encoding);
    const id_length = try craft_io.lengthInt(id, .varnum);
    const payload_and_id_length = payload_length + id_length;
    var bytes_encoded: usize = 0;
    if (conn.compression) |*comp| {
        // [length]
        // [data length] (or 0)
        // [compressed packet] (or uncompressed)
        if (payload_and_id_length > comp.threshold) {
            const data_length: i32 = @intCast(payload_and_id_length);
            // write the compressed data to comp.buf
            var compressor = try std.compress.zlib.compressor(comp.buf.writer(), .{});
            const compressor_writer = compressor.writer();
            bytes_encoded += try craft_io.encode(id, compressor_writer, allocator, .varnum);
            bytes_encoded += try craft_io.encode(packet, compressor_writer, allocator, encoding);
            try compressor.finish();

            // write the packet we actually intend to send
            const actual_size: usize = (try craft_io.length(data_length, allocator, .varnum)) + comp.buf.items.len;
            const conn_buf_writer = conn.buf.writer();
            bytes_encoded += try craft_io.encode(@as(i32, @intCast(actual_size)), conn_buf_writer, allocator, .varnum);
            bytes_encoded += try craft_io.encode(data_length, conn_buf_writer, allocator, .varnum);
            try conn.buf.appendSlice(comp.buf.items);
        } else {
            _ = try craft_io.encode(@as(i32, @intCast(payload_and_id_length + 1)), conn.buf.writer(), allocator, .varnum);
            try conn.buf.append(0); // data length == 0
            _ = try craft_io.encode(id, conn.buf.writer(), allocator, .varnum);
            _ = try craft_io.encode(packet, conn.buf.writer(), allocator, encoding);
            bytes_encoded += conn.buf.items.len;
        }
    } else {
        _ = try craft_io.encode(@as(i32, @intCast(payload_and_id_length)), conn.buf.writer(), allocator, .varnum);
        _ = try craft_io.encode(id, conn.buf.writer(), allocator, .varnum);
        _ = try craft_io.encode(packet, conn.buf.writer(), allocator, encoding);
        bytes_encoded += conn.buf.items.len;
    }

    const bytes_to_send = conn.buf.items;
    if (conn.encryption) |*encryption| {
        encryption.tx.encrypt(bytes_to_send);
    }

    const n_bytes_written = bytes_to_send.len;
    try conn.socket.writeAll(bytes_to_send);
    log.debug(
        "{*} [tx]: id={x}, bytes_written={d}, bytes_encoded={d}, payload_bytes={d}",
        .{
            conn,
            id,
            n_bytes_written,
            bytes_encoded,
            payload_length,
        },
    );
    return bytes_to_send.len;
}

pub fn setCompressionThreshold(conn: *Conn, threshold: usize) !void {
    if (conn.isCompressionEnabled()) {
        return error.CompressionAlreadyEnabled;
    }

    conn.compression = .{
        .buf = std.ArrayList(u8).init(conn.allocator),
        .threshold = threshold,
    };
    log.debug("{*} compression enabled, threshold = {n}", .{ conn, threshold });
}

pub fn isCompressionEnabled(conn: *const Conn) bool {
    return conn.compression != null;
}

pub fn enableEncryption(conn: *Conn, key: [cfb8.BYTES_SIZE]u8, iv: [cfb8.BYTES_SIZE]u8) !void {
    if (conn.isEncryptionEnabled()) {
        return error.EncryptionAlreadyEnabled;
    }

    conn.encryption = .{ .rx = .init(key, iv), .tx = .init(key, iv) };
    log.debug("{*} encryption enabled", .{conn});
}

pub fn isEncryptionEnabled(conn: *Conn) bool {
    return conn.encryption != null;
}

fn clearBuffers(conn: *Conn) void {
    conn.buf.clearRetainingCapacity();
    if (conn.compression) |*e| {
        e.buf.clearRetainingCapacity();
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
