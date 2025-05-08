const std = @import("std");
const CraftTypes = @import("CraftTypes.zig");

// state = handshake
pub const HandshakingPacket = struct {
    version: CraftTypes.VarInt,
    address: CraftTypes.String,
    port: u16,
    next_state: enum(i32) {
        status = 1,
        login = 2,
        transfer = 3,

        pub usingnamespace CraftTypes.AutoVarNumEnum(@This(), CraftTypes.VarInt);
    },

    pub fn deinit(self: @This()) void {
        self.address.deinit();
    }
};

// state = status
pub const StatusResponsePacket = struct {
    status: CraftTypes.String,

    pub fn deinit(self: @This()) void {
        self.status.deinit();
    }
};

pub const StatusPingPongPacket = struct {
    timestamp: i64,
};

test "encode handshaking packet" {
    const packet: HandshakingPacket = .{
        .version = @enumFromInt(770),
        .address = .init("localhost"),
        .port = 25565,
        .nextState = .status,
    };
    std.debug.print("version = {d}\n", .{packet.version});
    var buf = std.ArrayList(u8).init(std.testing.allocator);
    defer buf.deinit();
    _ = try CraftTypes.encode(packet, buf.writer());

    var expected = std.ArrayList(u8).init(std.testing.allocator);
    defer expected.deinit();

    _ = try CraftTypes.encode(packet.version, expected.writer());
    _ = try CraftTypes.encode(packet.address, expected.writer());
    _ = try CraftTypes.encode(packet.port, expected.writer());
    _ = try CraftTypes.encode(packet.nextState, expected.writer());

    try std.testing.expectEqualSlices(u8, expected.items, buf.items);
}

// state = login
pub const DisconnectPacket = struct {
    reason: CraftTypes.String,

    pub fn deinit(self: @This()) void {
        self.reason.deinit();
    }
};

pub const EncryptionRequestPacket = struct {
    server_id: CraftTypes.String,
    public_key: CraftTypes.String, // bytes
    verify_token: CraftTypes.String, // bytes
    should_authenticate: bool,

    pub fn deinit(self: @This()) void {
        self.server_id.deinit();
        self.public_key.deinit();
        self.verify_token.deinit();
    }
};

pub const LoginSuccessPacket = struct {
    uuid: CraftTypes.UUID,
    username: CraftTypes.String,
    properties: CraftTypes.LengthPrefixed(CraftTypes.VarInt, Property),

    pub const Property = struct {
        name: CraftTypes.String,
        value: CraftTypes.String,
        signature: ?CraftTypes.String,

        pub fn deinit(self: @This()) void {
            self.name.deinit();
            self.value.deinit();
            if (self.signature) |sig| {
                sig.deinit();
            }
        }
    };

    pub fn deinit(self: @This()) void {
        self.username.deinit();
        self.properties.deinit();
    }
};

pub const SetCompressionPacket = struct {
    threshold: CraftTypes.VarInt,
};

pub const LoginPluginRequestPacket = struct {
    message_id: CraftTypes.VarInt,
    channel: CraftTypes.String, // identifer
    data: CraftTypes.RemainingBytes,

    pub fn deinit(self: @This()) void {
        self.channel.deinit();
        self.data.deinit();
    }
};

pub const LoginCookieRequestPacket = struct {
    key: CraftTypes.String,

    pub fn deinit(self: @This()) void {
        self.key.deinit();
    }
};

pub const LoginStartPacket = struct {
    name: CraftTypes.String,
    uuid: CraftTypes.UUID,

    pub fn deinit(self: @This()) void {
        self.name.deinit();
    }
};

pub const LoginEncryptionResponsePacket = struct {
    sharedSecret: CraftTypes.String, // bytes
    verifyToken: CraftTypes.String, // bytes

    pub fn deinit(self: @This()) void {
        self.sharedSecret.deinit();
        self.verifyToken.deinit();
    }
};

pub const LoginPluginResponsePacket = struct {
    message_id: CraftTypes.VarInt,
    data: ?CraftTypes.RemainingBytes,

    pub fn deinit(self: @This()) void {
        if (self.data) |d| {
            d.deinit();
        }
    }
};

pub const LoginCookieResponsePacket = struct {
    key: CraftTypes.String,
    payload: ?CraftTypes.String, // optional bytes

    pub fn deinit(self: @This()) void {
        self.key.deinit();
        if (self.payload) |pld| {
            pld.deinit();
        }
    }
};
