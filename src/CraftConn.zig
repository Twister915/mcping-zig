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
    conn.buf.clearRetainingCapacity();

    const reader = conn.reader.reader();
    var bytes: usize = 0;
    var bodyLength: usize = @intCast((try CraftTypes.VarInt.decode(conn.allocator, reader, CraftTypes.VarInt.ByteSize)).unbox(&bytes).value);
    bytes += bodyLength;

    const packetIdDecoded = try CraftTypes.VarInt.decode(conn.allocator, reader, CraftTypes.VarInt.ByteSize);
    bodyLength -= packetIdDecoded.bytes;

    const body = try conn.buf.addManyAsSlice(bodyLength);
    try reader.readNoEof(body);

    return .{
        .id = packetIdDecoded.value,
        .data = body,
    };
}

pub fn writePacket(conn: *Conn, id: CraftTypes.VarInt, packet: anytype) !usize {
    if (std.meta.hasFn(@TypeOf(packet), "deinit")) {
        defer packet.deinit();
    }

    if (!std.meta.hasFn(@TypeOf(packet), "encode")) {
        @compileError("packet type " ++ @typeName(@TypeOf(packet)) ++ " does not have encode method");
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
