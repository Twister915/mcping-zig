const std = @import("std");
const craft_io = @import("io.zig");
const chat = @import("chat.zig");
const UUID = @import("UUID.zig");
const util = @import("util.zig");

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

    const Encoding = craft_io.Encoding(@This());
    pub const ENCODING: Encoding = .{
        .version = .varnum,
        .next_state = .varnum,
        .address = .{ .length = .{ .max = 0xFF } },
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

    _ = try craft_io.encode(pkt, std.testing.allocator, buf.writer(), HandshakingPacket);
    std.debug.print("\nin: {any}\nencoding: {any}\nout:{any}\n", .{ pkt, HandshakingPacket.ENCODING, buf.items });
}

// state = status
pub const StatusResponsePacket = struct {
    status: Status,

    const Encoding = craft_io.Encoding(@This());
    pub const ENCODING: Encoding = .{
        .status = .{
            .string_encoding = .{ .length = .{ .max = 0x7FFF } },
            .parse_options = .{ .ignore_unknown_fields = true },
        },
    };
};

pub const Status = struct {
    version: struct {
        name: []const u8,
        protocol: i32,
    },
    players: struct {
        max: i32,
        online: i32,
        sample: ?[]const struct {
            name: []const u8,
            id: UUID,
        } = null,
    },
    description: chat.Component = chat.Component.EMPTY,
    favicon: ?Favicon.Raw = null,
    enforces_secure_chat: ?bool = null,

    pub const CraftEncoding: type = craft_io.JsonEncoding;
};

pub const Favicon = struct {
    mime_type: []const u8,
    image: []const u8,

    const Raw = struct {
        mime_type: []const u8,
        image_base64: []const u8,

        const base64_decoder = std.base64.standard.Decoder;
        pub fn decode(raw: Raw, allocator: std.mem.Allocator) !Favicon {
            const size = try base64_decoder.calcSizeForSlice(raw.image_base64);
            const dest = try allocator.alloc(u8, size);
            try base64_decoder.decode(dest, raw.image_base64);
            return .{
                .mime_type = raw.mime_type,
                .image_bytes = dest,
            };
        }

        pub fn jsonParse(
            allocator: std.mem.Allocator,
            source: anytype,
            options: std.json.ParseOptions,
        ) !Raw {
            return fromRawStr(try std.json.innerParse(
                []const u8,
                allocator,
                source,
                options,
            ));
        }

        fn fromRawStr(str: []const u8) Raw {
            var rest = str;
            _ = util.stripPrefix(u8, &rest, "data:");
            var mime_type: []const u8 = "";
            if (std.mem.indexOfScalar(u8, rest, ';')) |semicolon_at| {
                mime_type = rest[0..semicolon_at];
                rest = rest[semicolon_at + 1 ..];
            }

            _ = util.stripPrefix(u8, &rest, "base64,");
            return .{
                .mime_type = mime_type,
                .image_base64 = rest,
            };
        }
    };
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

    const Encoding = craft_io.Encoding(@This());
    pub const ENCODING: Encoding = .{ .server_id = .{ .length = .{ .max = 20 } } };
};

pub const LoginSuccessPacket = struct {
    uuid: UUID,
    username: []const u8,
    properties: []const Property,

    const Encoding = craft_io.Encoding(@This());
    pub const ENCODING: Encoding = .{ .username = .{ .length = .{ .max = 0x10 } } };

    pub const Property = struct {
        name: []const u8,
        value: []const u8,
        signature: ?[]const u8,

        const PropertyEncoding = craft_io.Encoding(@This());
        pub const ENCODING: PropertyEncoding = .{
            .name = .{ .length = .{ .max = 0x40 } },
            .value = .{ .length = .{ .max = 0x7FFF } },
            .signature = .{ .length = .{ .max = 0x400 } },
        };
    };
};

test "encode login success packet" {
    const pkt: LoginSuccessPacket = .{
        .uuid = UUID.random(std.crypto.random),
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

    const login_success_encoding: craft_io.Encoding(LoginSuccessPacket) = .{};
    _ = try craft_io.encode(pkt, buf.writer(), std.testing.allocator, login_success_encoding);
    std.debug.print(
        "\nin: {any}\nencoding: {any}\nout:{any}\nlength(pkt): pred={d}, act={d}\n",
        .{
            pkt,
            login_success_encoding,
            buf.items,
            try craft_io.length(pkt, std.testing.allocator, login_success_encoding),
            buf.items.len,
        },
    );
}

pub const SetCompressionPacket = struct {
    threshold: i32,

    pub const Encoding = craft_io.Encoding(@This());
    pub const ENCODING: Encoding = .{ .threshold = .varnum };
};

pub const LoginPluginRequestPacket = struct {
    message_id: i32,
    channel: []const u8, // identifer
    data: []const u8,

    pub const Encoding = craft_io.Encoding(@This());
    pub const ENCODING: Encoding = .{
        .channel = .{ .length = .{ .max = 0x7FFF } },
        .data = .{ .length = .{ .prefix = .disabled, .max = 0x100000 } },
    };
};

pub const LoginCookieRequestPacket = struct {
    key: []const u8,
};

pub const LoginStartPacket = struct {
    name: []const u8,
    uuid: UUID,

    pub const Encoding = craft_io.Encoding(@This());
    pub const ENCODING: Encoding = .{
        .name = .{ .length = .{ .max = 0x10 } },
    };
};

pub const LoginEncryptionResponsePacket = struct {
    shared_secret: []const u8, // bytes
    verify_token: []const u8, // bytes
};

pub const LoginPluginResponsePacket = struct {
    message_id: i32,
    data: ?[]const u8,

    pub const Encoding = craft_io.Encoding(@This());
    pub const ENCODING: Encoding = .{
        .message_id = .varnum,
        .data = .{ .length = .{ .prefix = .disabled, .max = 0x100000 } },
    };
};

pub const LoginCookieResponsePacket = struct {
    key: []const u8,
    payload: ?[]const u8, // optional bytes

    pub const Encoding = craft_io.Encoding(@This());
    pub const ENCODING: Encoding = .{
        .key = .{ .length = .{ .max = 0x7FFF } },
        .payload = .{ .length = .{ .max = 0x1400 } },
    };
};

test "encoding numeric tagged union" {
    const PlayerTarget = struct {
        player_name: []const u8,
        player_id: UUID,

        pub const Encoding = craft_io.Encoding(@This());
        pub const ENCODING: Encoding = .{
            .player_name = .{ .length = .{ .max = 12 } },
        };
    };

    const ScoreboardActionTag = enum(i32) { add, remove, clear };

    const ScoreboardAction = union(ScoreboardActionTag) {
        add: PlayerTarget,
        remove: PlayerTarget,
        clear,

        const Encoding = craft_io.Encoding(@This());
        pub const ENCODING: Encoding = .{ .tag = .varnum };
    };

    const ScoreboardPacket = struct {
        actions: []const ScoreboardAction,
    };

    const sb_pkt: ScoreboardPacket = .{ .actions = &.{
        .{ .remove = .{
            .player_name = "joey",
            .player_id = UUID.random(std.crypto.random),
        } },
        .{ .add = .{
            .player_name = "bill",
            .player_id = UUID.random(std.crypto.random),
        } },
        .{ .add = .{
            .player_name = "albert",
            .player_id = UUID.random(std.crypto.random),
        } },
        .{ .remove = .{
            .player_name = "the devil",
            .player_id = UUID.random(std.crypto.random),
        } },
    } };

    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const allocator = arena.allocator();

    var buf = std.ArrayList(u8).init(allocator);

    const sb_pkt_encoding: craft_io.Encoding(ScoreboardPacket) = .{};
    _ = try craft_io.encode(sb_pkt, allocator, buf.writer(), .{});
    std.debug.print("\nin: {any}\nencoding: {any}\nout:{any}\n", .{ sb_pkt, sb_pkt_encoding, buf.items });

    var stream = std.io.fixedBufferStream(buf.items);
    const sb_pkt_decoded = (try craft_io.decode(
        ScoreboardPacket,
        stream.reader(),
        &arena,
        sb_pkt_encoding,
    )).unwrap(null);
    std.debug.print("\ndecoded: {any}\n", .{sb_pkt_decoded});
}
