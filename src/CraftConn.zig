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
    conn.buf.deinit();
    conn.socket.close();
    log.debug("{*} connection shutdown", .{conn});
    conn.allocator.free(conn.address);
}

pub const ReadPkt = struct {
    id: i32,
    // we're borrowing this memory from the connection, so that's why there's const and no deinit
    payload: []const u8,
    bytes_read: usize,

    const Self = @This();

    // if you call this, we decode the packet into owned memory (call deinit() on the returned T)
    pub fn decodeAs(self: Self, comptime T: type, arena_allocator: *std.heap.ArenaAllocator) !T {
        const encoding = comptime defaultPacketEncoding(T);
        var stream = std.io.fixedBufferStream(self.payload);
        var counting_stream = std.io.countingReader(stream.reader());
        const decoded: craft_io.Decoded(T) = try craft_io.decode(
            T,
            counting_stream.reader(),
            arena_allocator,
            encoding,
        );
        const expected_len = self.payload.len;
        const actual_bytes_decoded: usize = @intCast(counting_stream.bytes_read);
        if (decoded.bytes_read != expected_len) {
            log.warn(
                "packet 0x{X:0>2} not parsed completely, real_size={d}, read_bytes={d}, reported_bytes_read={d}",
                .{
                    @as(u32, @intCast(self.id)),
                    expected_len,
                    actual_bytes_decoded,
                    decoded.bytes_read,
                },
            );
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

    // decode the packet length, which is always uncompressed
    const pkt_length_decoded = try craft_io.decodeInt(i32, reader, .varnum);
    const pkt_length: usize = @intCast(pkt_length_decoded.value);
    // start tracking how many bytes we read off the wire, and how many bytes are left
    var bytes_read = pkt_length_decoded.bytes_read;
    var bytes_left = pkt_length;

    // track how many bytes we read from the underlying reader by wrapping it with a counting reader
    var socket_read_counter = std.io.countingReader(reader);
    const counting_reader = socket_read_counter.reader();

    var pkt: ReadPkt = undefined;
    var did_read_pkt = false;
    var expected_data_length: usize = undefined;

    if (conn.compression != null) {
        // if compression is enabled, then we must decode the data length (uncompressed)
        const data_length_decoded = try craft_io.decodeInt(i32, counting_reader, .varnum);
        const data_length: usize = @intCast(data_length_decoded.value);
        bytes_read += data_length_decoded.bytes_read;
        bytes_left -= data_length_decoded.bytes_read;

        if (data_length > 0) {
            // if data_length is non-zero, then the bytes which follow are compressed
            expected_data_length = data_length;

            // create a decompressing reader
            var decompressor = std.compress.zlib.decompressor(counting_reader);
            const decompress_reader = decompressor.reader();
            log.debug(
                "{*} [rx:decompress] data_length={d}, bytes_left={d}, bytes_read={d}",
                .{ conn, data_length, bytes_left, bytes_read },
            );
            // read the id + payload out of the decompress reader
            pkt = try conn.readPacketWithLengthFrom(decompress_reader, data_length, bytes_read);
            did_read_pkt = true;
        } else {
            // if data_length is 0, then the packet is not compressed, and the expected length is pkt_length - 1 (1 byte for 0 data length)
            expected_data_length = pkt_length - 1;
        }
    } else {
        // if compression is disabled, then the id + payload is just all the remaining bytes which == pkt_length
        expected_data_length = pkt_length;
    }

    // did_read_pkt = true when compression is enabled and the packet exceeds the threshold (and was decompressed)
    // so if did_read_pkt == false, then we should read the uncompressed packet data from the reader
    if (!did_read_pkt) {
        pkt = try conn.readPacketWithLengthFrom(counting_reader, bytes_left, bytes_read);
    }

    // now check if we read all the bytes we were supposed to
    const actual_bytes_read: usize = @intCast(socket_read_counter.bytes_read);
    const extra_bytes_available: usize = pkt_length - actual_bytes_read;

    // when we decompress, there are sometimes extra bytes left at the end (for some reason), so we will skip those bytes
    if (extra_bytes_available > 0) {
        try reader.skipBytes(extra_bytes_available, .{ .buf_size = 32 });
    }

    // if the decoded packet length doesn't match the expected data length, something went wrong, which means the entire
    // connection is in an invalid state, and we cannot proceed
    if (pkt.bytes_read != expected_data_length) {
        return error.UnexpectedBytesRead;
    }

    return pkt;
}

fn readPacketWithLengthFrom(conn: *Conn, reader: anytype, size: usize, bytes_already_read: usize) !ReadPkt {
    var bytes_decoded = bytes_already_read;
    const id_and_payload = try conn.buf.addManyAsSlice(size);
    try reader.readNoEof(id_and_payload);
    bytes_decoded += size;

    var id_payload_stream = std.io.fixedBufferStream(id_and_payload);
    const id_decoded = try craft_io.decodeInt(i32, id_payload_stream.reader(), .varnum);
    const id = id_decoded.value;
    const payload = id_and_payload[id_decoded.bytes_read..]; // skip the bytes for the ID

    log.debug(
        "{*} [rx]: id=0x{x}, bytes_decoded={d}, payload_bytes={d}",
        .{
            conn,
            id,
            bytes_decoded,
            payload.len,
        },
    );

    return .{ .id = id, .payload = payload, .bytes_read = size };
}

pub fn writePacket(conn: *Conn, id: i32, packet: anytype, diag: craft_io.Diag) !usize {
    return conn.writePacketWithEncoding(
        id,
        packet,
        diag,
        comptime defaultPacketEncoding(@TypeOf(packet)),
    );
}

pub fn writePacketWithEncoding(
    conn: *Conn,
    id: i32,
    packet: anytype,
    diag: craft_io.Diag,
    comptime encoding: craft_io.Encoding(@TypeOf(packet)),
) !usize {
    conn.clearBuffers();

    var arena_allocator = std.heap.ArenaAllocator.init(conn.allocator);
    defer arena_allocator.deinit();
    const allocator = arena_allocator.allocator();

    const payload_length = try craft_io.length(
        packet,
        allocator,
        try diag.child(.packet_body),
        encoding,
    );
    const id_length = try craft_io.length(
        id,
        allocator,
        try diag.child(.packet_id),
        .varnum,
    );
    const data_length = payload_length + id_length;
    const buf_writer = conn.buf.writer();
    var bytes_to_write: []u8 = undefined;
    if (conn.compression) |*comp| {
        // compression is enabled
        if (data_length > comp.threshold) {
            // we already know the length of the uncompressed packet, so we can also calculate the length of
            // the data length at this time
            const data_length_length = try craft_io.length(
                data_length,
                allocator,
                try diag.child(.packet_data_length),
                .varnum,
            );

            // reserve extra space in conn.buf to encode two numbers: [total length], [uncompressed data length]
            //
            // we already know [uncompressed data length], but we don't know the total length until compression is
            // complete, so we will reserve 5 + lengthOf(uncompressed data length) bytes, since a VarInt can have
            // a maximum size of 5 bytes.
            const prefix_size = craft_io.MAX_VAR_INT_LENGTH + data_length_length;
            const prefix_buf = try conn.buf.addManyAsSlice(prefix_size);

            // compress directly to conn.buf (after the prefix space we reserved)
            var compressor = try std.compress.zlib.compressor(buf_writer, .{});
            const compressor_writer = compressor.writer();
            _ = try craft_io.encode(
                id,
                compressor_writer,
                allocator,
                try diag.child(.packet_id),
                .varnum,
            );
            _ = try craft_io.encode(
                packet,
                compressor_writer,
                allocator,
                try diag.child(.packet_body),
                encoding,
            );
            try compressor.finish();

            // calculate how many bytes the compressor wrote, which will give us the # of bytes in compressed(id + payload)
            const compressed_payload_length = conn.buf.items.len - prefix_size;
            // total length is the data_length_length + the number of bytes in the compressed(id + payload)
            const total_length: i32 = @intCast(data_length_length + compressed_payload_length);
            // this is the number of bytes required to encode the total_length
            const total_length_length = try craft_io.length(
                total_length,
                allocator,
                try diag.child(.packet_length),
                .varnum,
            );

            // now we will encode the total_length such that it comes right before the data_length.
            // we do this by skipping whatever bytes we don't need, and start writing at an index higher than 0
            const prefix_offset = prefix_buf.len - (total_length_length + data_length_length);
            const prefix_dst = prefix_buf[prefix_offset..];
            var prefix_stream = std.io.fixedBufferStream(prefix_dst);
            const prefix_writer = prefix_stream.writer();
            // encode total length
            _ = try craft_io.encode(
                total_length,
                prefix_writer,
                allocator,
                try diag.child(.packet_length),
                .varnum,
            );
            // encode data length
            _ = try craft_io.encode(
                @as(i32, @intCast(data_length)),
                prefix_writer,
                allocator,
                try diag.child(.packet_data_length),
                .varnum,
            );
            // by definition, the compressed data should immediately follow the data_length
            bytes_to_write = conn.buf.items[prefix_offset..];
        } else {
            // compression is enabled but the threshold is not met, so we can just write the uncompressed packet, and a data_length of 0
            // total_length is trivial to calculate... data_length + 1 (because of the extra 0 for data_length=0)

            // encode total_length
            _ = try craft_io.encode(
                @as(i32, @intCast(data_length + 1)),
                buf_writer,
                allocator,
                try diag.child(.packet_length),
                .varnum,
            );
            // encode data_length=0
            try buf_writer.writeByte(0);
            // encode id + payload
            _ = try craft_io.encode(
                id,
                buf_writer,
                allocator,
                try diag.child(.packet_id),
                .varnum,
            );
            _ = try craft_io.encode(
                packet,
                buf_writer,
                allocator,
                try diag.child(.packet_body),
                encoding,
            );
            bytes_to_write = conn.buf.items;
        }
    } else {
        // compression is disabled, so we just write total_length, id, packet
        _ = try craft_io.encode(
            @as(i32, @intCast(data_length)),
            buf_writer,
            allocator,
            try diag.child(.packet_length),
            .varnum,
        );
        _ = try craft_io.encode(
            id,
            buf_writer,
            allocator,
            try diag.child(.packet_id),
            .varnum,
        );
        _ = try craft_io.encode(
            packet,
            buf_writer,
            allocator,
            try diag.child(.packet_body),
            encoding,
        );
        bytes_to_write = conn.buf.items;
    }

    if (conn.encryption) |*encryption| {
        encryption.tx.encrypt(bytes_to_write);
    }

    // send the prepared bytes over the socket
    try conn.socket.writeAll(bytes_to_write);

    log.debug(
        "{*} [tx]: id=0x{x}, bytes_written={d}, payload_bytes={d}",
        .{
            conn,
            id,
            bytes_to_write.len,
            payload_length,
        },
    );
    return bytes_to_write.len;
}

pub fn setCompressionThreshold(conn: *Conn, threshold: usize) !void {
    if (conn.isCompressionEnabled()) {
        return error.CompressionAlreadyEnabled;
    }

    conn.compression = .{ .threshold = threshold };
    log.debug("{*} compression enabled, threshold = {d}", .{ conn, threshold });
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
