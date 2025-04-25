const std = @import("std");
const CraftTypes = @import("CraftTypes.zig");

pub const EmptyPacket = CraftTypes.Composite(struct {});

pub const HandshakingPacket = CraftTypes.Composite(struct {
    version: CraftTypes.VarInt,
    address: CraftTypes.String,
    port: CraftTypes.UShort,
    nextState: CraftTypes.IntEnum(CraftTypes.VarInt, enum(i32) {
        status = 1,
        login = 2,
        transfer = 3,
    }),
});

pub const StatusResponsePacket = CraftTypes.Composite(struct {
    status: CraftTypes.String,
});

pub const StatusPingRequestPacket = CraftTypes.Composite(struct {
    timestamp: CraftTypes.Long,
});

pub const StatusPongResponsePacket = CraftTypes.Composite(struct {
    timestamp: CraftTypes.Long,
});

test "encode handshaking packet" {
    const packet = HandshakingPacket.init(.{
        .version = .init(770),
        .address = .init("localhost"),
        .port = .init(25565),
        .nextState = .init(.status),
    });
    var buf = std.ArrayList(u8).init(std.testing.allocator);
    defer buf.deinit();
    _ = try packet.encode(buf.writer());

    var expected = std.ArrayList(u8).init(std.testing.allocator);
    defer expected.deinit();

    _ = try packet.payload.version.encode(expected.writer());
    _ = try packet.payload.address.encode(expected.writer());
    _ = try packet.payload.port.encode(expected.writer());
    _ = try packet.payload.nextState.encode(expected.writer());

    try std.testing.expectEqualSlices(u8, expected.items, buf.items);
}
