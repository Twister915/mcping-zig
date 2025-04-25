const std = @import("std");
const CraftTypes = @import("CraftTypes.zig");

// util packets
pub const EmptyPacket = struct {
    pub usingnamespace CraftTypes.Struct(@This());
};

// state = handshake
pub const HandshakingPacket = struct {
    version: CraftTypes.VarInt,
    address: CraftTypes.String,
    port: CraftTypes.UShort,
    nextState: CraftTypes.IntEnum(CraftTypes.VarInt, enum(i32) {
        status = 1,
        login = 2,
        transfer = 3,
    }),

    pub usingnamespace CraftTypes.Struct(@This());
};

// state = status
pub const StatusResponsePacket = struct {
    status: CraftTypes.String,

    pub usingnamespace CraftTypes.Struct(@This());
};

pub const StatusPingPongPacket = struct {
    timestamp: CraftTypes.Long,

    pub usingnamespace CraftTypes.Struct(@This());
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

// state = login
pub const DisconnectPacket = struct {
    reason: CraftTypes.String,

    pub usingnamespace CraftTypes.Struct(@This());
};

pub const EncryptionRequestPacket = struct {
    serverId: CraftTypes.String,
    publicKey: CraftTypes.String, // bytes
    verifyToken: CraftTypes.String, // bytes
    shouldAuthenticate: CraftTypes.Bool,

    pub usingnamespace CraftTypes.Struct(@This());
};

pub const LoginSuccessPacket = struct {
    uuid: CraftTypes.UUID,
    username: CraftTypes.String,
    properties: CraftTypes.CountedArray(CraftTypes.VarInt, Property),

    pub const Property = struct {
        name: CraftTypes.String,
        value: CraftTypes.String,
        signature: CraftTypes.Optional(CraftTypes.String),

        pub usingnamespace CraftTypes.Struct(@This());
    };

    pub usingnamespace CraftTypes.Struct(@This());
};

pub const SetCompressionPacket = struct {
    threshold: CraftTypes.VarInt,

    pub usingnamespace CraftTypes.Struct(@This());
};

pub const LoginPluginRequestPacket = struct {
    messageId: CraftTypes.VarInt,
    channel: CraftTypes.String, // identifer
    data: CraftTypes.RemainingBytes,

    pub usingnamespace CraftTypes.Struct(@This());
};

pub const LoginCookieRequestPacket = struct {
    key: CraftTypes.String,

    pub usingnamespace CraftTypes.Struct(@This());
};

pub const LoginStartPacket = struct {
    name: CraftTypes.String,
    uuid: CraftTypes.UUID,

    pub usingnamespace CraftTypes.Struct(@This());
};

pub const LoginEncryptionResponsePacket = struct {
    sharedSecret: CraftTypes.String, // bytes
    verifyToken: CraftTypes.String, // bytes

    pub usingnamespace CraftTypes.Struct(@This());
};

pub const LoginPluginResponsePacket = struct {
    messageId: CraftTypes.VarInt,
    data: CraftTypes.Optional(CraftTypes.RemainingBytes),

    pub usingnamespace CraftTypes.Struct(@This());
};

pub const LoginCookieResponsePacket = struct {
    key: CraftTypes.String,
    payload: CraftTypes.Optional(CraftTypes.String), // optional bytes

    pub usingnamespace CraftTypes.Struct(@This());
};
