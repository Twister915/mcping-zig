const std = @import("std");
const CraftTypes = @import("CraftTypes.zig");

pub const EmptyPacket = struct {
    pub usingnamespace CraftTypes.Composite(@This());
};

pub const HandshakingPacket = struct {
    version: CraftTypes.VarInt,
    address: CraftTypes.String,
    port: CraftTypes.UShort,
    nextState: CraftTypes.IntEnum(CraftTypes.VarInt, enum(i32) {
        status = 1,
        login = 2,
        transfer = 3,
    }),

    pub usingnamespace CraftTypes.Composite(@This());
};

pub const StatusResponsePacket = struct {
    status: CraftTypes.String,

    pub usingnamespace CraftTypes.Composite(@This());
};

pub const StatusPingPongPacket = struct {
    timestamp: CraftTypes.Long,

    pub usingnamespace CraftTypes.Composite(@This());
};

test "encode handshaking packet" {
    const packet: HandshakingPacket = .{
        .version = .init(770),
        .address = .init("localhost"),
        .port = .init(25565),
        .nextState = .init(.status),
    };
    std.debug.print("version = {d}\n", .{packet.version.value});
    var buf = std.ArrayList(u8).init(std.testing.allocator);
    defer buf.deinit();
    _ = try packet.encode(buf.writer());

    var expected = std.ArrayList(u8).init(std.testing.allocator);
    defer expected.deinit();

    _ = try packet.version.encode(expected.writer());
    _ = try packet.address.encode(expected.writer());
    _ = try packet.port.encode(expected.writer());
    _ = try packet.nextState.encode(expected.writer());

    try std.testing.expectEqualSlices(u8, expected.items, buf.items);
}
