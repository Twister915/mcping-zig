const std = @import("std");
const net = std.net;
const CraftTypes = @import("CraftTypes.zig");

const BUF_SIZE = 256;
const bufReader = std.io.BufferedReader(BUF_SIZE, net.Stream.Reader);

socket: net.Stream,
reader: bufReader,
buf: std.ArrayList(u8),
allocator: std.mem.Allocator,

const Conn = @This();

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
    defer conn.socket.close();
    defer conn.buf.deinit();
}

pub const ReadPkt = struct {
    id: CraftTypes.VarInt,
    data: []const u8,
    conn: *const Conn,

    const Self = @This();

    pub fn decodeAs(self: Self, comptime T: type) !CraftTypes.Decoded(T) {
        var stream = std.io.fixedBufferStream(self.data);
        return T.decode(self.conn.allocator, stream.reader());
    }
};

pub fn readPacket(conn: *Conn) !CraftTypes.Decoded(ReadPkt) {
    conn.buf.clearRetainingCapacity();

    const reader = conn.reader.reader();
    var bytes: usize = 0;
    var bodyLength: usize = @intCast((try CraftTypes.VarInt.decode(conn.allocator, reader)).unbox(&bytes).value);
    bytes += bodyLength;

    const packetIdDecoded = try CraftTypes.VarInt.decode(conn.allocator, reader);
    defer packetIdDecoded.deinit(); // basically a no-op
    bodyLength -= packetIdDecoded.bytes;

    const body = try conn.buf.addManyAsSlice(bodyLength);
    try reader.readNoEof(body);

    return .{
        .value = .{
            .id = packetIdDecoded.value,
            .data = body,
            .conn = conn,
        },
        .bytes = bytes,
    };
}

pub fn writePacket(id: CraftTypes.VarInt, conn: *Conn, comptime T: type, packet: T) !usize {
    if (std.meta.hasFn(T, "deinit")) {
        defer packet.deinit();
    }

    conn.buf.clearRetainingCapacity();
    const lengthPrefixBuf = try conn.buf.addManyAsSlice(CraftTypes.VarInt.ByteSize);

    const writer = conn.buf.writer();
    const idSize: usize = try id.encode(writer);
    const bodySize: usize = try packet.encode(writer);

    const l: CraftTypes.VarInt = .init(@intCast(idSize + bodySize));
    var lengthPrefixStream = std.io.fixedBufferStream(lengthPrefixBuf);
    const lBytes = try l.encode(lengthPrefixStream.writer());

    const startIdx = CraftTypes.VarInt.ByteSize - lBytes;
    if (startIdx > 0) {
        std.mem.copyBackwards(
            u8,
            conn.buf.items[startIdx..CraftTypes.VarInt.ByteSize],
            conn.buf.items[0..lBytes],
        );
    }
    const endIdx = startIdx + lBytes + idSize + bodySize;
    const packetBuf = conn.buf.items[startIdx..endIdx];
    try conn.socket.writeAll(packetBuf);
    return packetBuf.len;
}
