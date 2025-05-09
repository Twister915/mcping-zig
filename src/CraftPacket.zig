const std = @import("std");
const CraftTypes = @import("CraftTypes.zig");

// state = handshake
pub const HandshakingPacket = struct {
    version: i32,
    address: []const u8,
    port: u16,
    next_state: enum(i32) {
        status = 1,
        login = 2,
        transfer = 3,
    },

    const Encoding = CraftTypes.Encoding(@This());
    pub const ENCODING: Encoding = .{
        .version = .varnum,
        .next_state = .varnum,
    };
};

test "encode handshaking packet" {
    const pkt: HandshakingPacket = .{
        .version = 770,
        .address = "rpi4.jhome",
        .port = 25565,
        .next_state = .status,
    };

    var buf = std.ArrayList(u8).init(std.testing.allocator);
    defer buf.deinit();

    _ = try CraftTypes.encode(pkt, buf.writer(), .{});
    std.debug.print("\nin: {any}\nencoding: {any}\nout:{any}\n", .{ pkt, HandshakingPacket.ENCODING, buf.items });
}

// state = status
pub const StatusResponsePacket = struct {
    status: []const u8,
};

pub const StatusPingPongPacket = struct {
    timestamp: i64,
};

// state = login
pub const DisconnectPacket = struct {
    reason: []const u8,
};

pub const EncryptionRequestPacket = struct {
    server_id: []const u8,
    public_key: []const u8, // bytes
    verify_token: []const u8, // bytes
    should_authenticate: bool,
};

pub const LoginSuccessPacket = struct {
    uuid: CraftTypes.UUID,
    username: []const u8,
    properties: []const Property,

    pub const Property = struct {
        name: []const u8,
        value: []const u8,
        signature: ?[]const u8,
    };
};

test "encode login success packet" {
    const pkt: LoginSuccessPacket = .{
        .uuid = CraftTypes.UUID.random(std.crypto.random),
        .username = "Notch",
        .properties = &.{
            .{
                .name = "coolness",
                .value = "100",
                .signature = null,
            },
            .{
                .name = "is_founder",
                .value = "true",
                .signature = "signed by Notch",
            },
        },
    };

    var buf = std.ArrayList(u8).init(std.testing.allocator);
    defer buf.deinit();

    const login_success_encoding: CraftTypes.Encoding(LoginSuccessPacket) = .{};
    _ = try CraftTypes.encode(pkt, buf.writer(), login_success_encoding);
    std.debug.print("\nin: {any}\nencoding: {any}\nout:{any}\n", .{ pkt, login_success_encoding, buf.items });
}

pub const SetCompressionPacket = struct {
    threshold: i32,

    pub const Encoding = CraftTypes.Encoding(@This());
    pub const ENCODING: Encoding = .{ .threshold = .varnum };
};

pub const LoginPluginRequestPacket = struct {
    message_id: i32,
    channel: []const u8, // identifer
    data: []const u8,

    pub const Encoding = CraftTypes.Encoding(@This());
    pub const ENCODING: Encoding = .{
        .message_id = .default,
        .channel = .{},
        .data = .{ .length_prefix = .disabled },
    };
};

pub const LoginCookieRequestPacket = struct {
    key: []const u8,

    pub const Encoding = CraftTypes.Encoding(@This());
    pub const ENCODING: Encoding = .{};
};

pub const LoginStartPacket = struct {
    name: []const u8,
    uuid: CraftTypes.UUID,

    pub const Encoding = CraftTypes.Encoding(@This());
    pub const ENCODING: Encoding = .{};
};

pub const LoginEncryptionResponsePacket = struct {
    shared_secret: []const u8, // bytes
    verify_token: []const u8, // bytes

    pub const Encoding = CraftTypes.Encoding(@This());
    pub const ENCODING: Encoding = .{};
};

pub const LoginPluginResponsePacket = struct {
    message_id: i32,
    data: ?[]const u8,

    pub const Encoding = CraftTypes.Encoding(@This());
    pub const ENCODING: Encoding = .{
        .message_id = .varnum,
        .data = .{ .length_prefix = .disabled },
    };
};

pub const LoginCookieResponsePacket = struct {
    key: []const u8,
    payload: ?[]const u8, // optional bytes

    pub const Encoding = CraftTypes.Encoding(@This());
    pub const ENCODING: Encoding = .{};
};

test "encoding numeric tagged union" {
    const PlayerTarget = struct {
        player_name: []const u8,
        player_id: CraftTypes.UUID,
    };

    const ScoreboardActionTag = enum(i32) { add, remove, clear };

    const ScoreboardAction = union(ScoreboardActionTag) {
        add: PlayerTarget,
        remove: PlayerTarget,
        clear,

        const Encoding = CraftTypes.Encoding(@This());
        pub const ENCODING: Encoding = .{ .tag = .varnum };
    };

    const ScoreboardPacket = struct {
        actions: []const ScoreboardAction,
    };

    const sb_pkt: ScoreboardPacket = .{ .actions = &.{
        .{ .remove = .{
            .player_name = "joey",
            .player_id = CraftTypes.UUID.random(std.crypto.random),
        } },
        .{ .add = .{
            .player_name = "bill",
            .player_id = CraftTypes.UUID.random(std.crypto.random),
        } },
        .{ .add = .{
            .player_name = "albert",
            .player_id = CraftTypes.UUID.random(std.crypto.random),
        } },
        .{ .remove = .{
            .player_name = "the devil",
            .player_id = CraftTypes.UUID.random(std.crypto.random),
        } },
    } };

    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const allocator = arena.allocator();

    var buf = std.ArrayList(u8).init(allocator);

    const sb_pkt_encoding: CraftTypes.Encoding(ScoreboardPacket) = .{};
    _ = try CraftTypes.encode(sb_pkt, buf.writer(), .{});
    std.debug.print("\nin: {any}\nencoding: {any}\nout:{any}\n", .{ sb_pkt, sb_pkt_encoding, buf.items });

    var stream = std.io.fixedBufferStream(buf.items);
    const sb_pkt_decoded = (try CraftTypes.decode(
        ScoreboardPacket,
        stream.reader(),
        allocator,
        sb_pkt_encoding,
    )).unwrap(null);
    std.debug.print("\ndecoded: {any}\n", .{sb_pkt_decoded});
}
