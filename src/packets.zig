const std = @import("std");
const craft_io = @import("io.zig");
const chat = @import("chat.zig");
const UUID = @import("UUID.zig");
const util = @import("util.zig");
const nbt = @import("nbt.zig");

const MAX_IDENTIFIER_SIZE: usize = 0x7FFF;

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
        .address = .{ .max_items = 0xFF },
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

    _ = try craft_io.encode(pkt, buf.writer(), std.testing.allocator, .{}, HandshakingPacket.ENCODING);
    std.debug.print("\nin: {any}\nencoding: {any}\nout:{any}\n", .{ pkt, HandshakingPacket.ENCODING, buf.items });
}

// state = status
pub const StatusResponsePacket = struct {
    status: Status,

    const Encoding = craft_io.Encoding(@This());
    pub const ENCODING: Encoding = .{
        .status = .{
            .string_encoding = .{ .max_items = MAX_IDENTIFIER_SIZE },
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
                .image = dest,
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
    pub const ENCODING: Encoding = .{ .server_id = .{ .max_items = 20 } };
};

pub const LoginSuccessPacket = struct {
    uuid: UUID,
    username: []const u8,
    properties: []const Property,

    const Encoding = craft_io.Encoding(@This());
    pub const ENCODING: Encoding = .{ .username = .{ .max_items = 0x10 } };

    pub const Property = struct {
        name: []const u8,
        value: []const u8,
        signature: ?[]const u8,

        const PropertyEncoding = craft_io.Encoding(@This());
        pub const ENCODING: PropertyEncoding = .{
            .name = .{ .max_items = 0x40 },
            .value = .{ .max_items = MAX_IDENTIFIER_SIZE },
            .signature = .{ .max_items = 0x400 },
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
    _ = try craft_io.encode(pkt, buf.writer(), std.testing.allocator, .{}, login_success_encoding);
    std.debug.print(
        "\nin: {any}\nencoding: {any}\nout:{any}\nlength(pkt): pred={d}, act={d}\n",
        .{
            pkt,
            login_success_encoding,
            buf.items,
            try craft_io.length(pkt, std.testing.allocator, .{}, login_success_encoding),
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
        .channel = .{ .max_items = MAX_IDENTIFIER_SIZE },
        .data = .{ .max_items = 0x100000, .length = .disabled },
    };
};

pub const CookieRequestPacket = struct {
    key: []const u8,
};

pub const LoginStartPacket = struct {
    name: []const u8,
    uuid: UUID,

    pub const Encoding = craft_io.Encoding(@This());
    pub const ENCODING: Encoding = .{
        .name = .{ .max_items = 0x10 },
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
        .data = .{ .max_items = 0x100000, .length = .disabled },
    };
};

pub const CookieResponsePacket = struct {
    key: []const u8,
    payload: ?[]const u8, // optional bytes

    pub const Encoding = craft_io.Encoding(@This());
    pub const ENCODING: Encoding = .{
        .key = .{ .max_items = MAX_IDENTIFIER_SIZE },
        .payload = .{ .max_items = 0x1400 },
    };
};

pub const ConfigClientInformationPacket = struct {
    locale: []const u8,
    view_distance: u8,
    chat_mode: enum(i32) {
        enabled = 0,
        commands_only = 1,
        hidden = 2,
    },
    chat_colors: bool,
    displayed_skin_parts: packed struct {
        cape_enabled: bool, // 0x01
        jacket_enabled: bool, // 0x02
        left_sleeve_enabled: bool, // 0x04
        right_sleeve_enabled: bool, // 0x08
        left_pants_leg_enabled: bool, // 0x10
        right_pants_leg_enabled: bool, // 0x20
        hat_enabled: bool, // 0x40
    },
    main_hand: enum(i32) {
        left = 0,
        right = 1,
    },
    enable_text_filtering: bool,
    allow_server_listings: bool,
    particle_status: enum(i32) {
        all = 0,
        decreased = 1,
        minimal = 2,
    },

    pub const Encoding = craft_io.Encoding(@This());
    pub const ENCODING: Encoding = .{
        .locale = .{ .max_items = 16 },
        .chat_mode = .varnum,
        .main_hand = .varnum,
        .particle_status = .varnum,
    };
};

test "encoding of config client information packet" {
    const packet: ConfigClientInformationPacket = .{
        .locale = "en_US",
        .view_distance = 16,
        .chat_mode = .enabled,
        .chat_colors = true,
        .displayed_skin_parts = .{
            .cape_enabled = true,
            .jacket_enabled = true,
            .left_sleeve_enabled = true,
            .right_sleeve_enabled = true,
            .left_pants_leg_enabled = true,
            .right_pants_leg_enabled = true,
            .hat_enabled = true,
        },
        .main_hand = .right,
        .enable_text_filtering = false,
        .allow_server_listings = true,
        .particle_status = .all,
    };
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var buf = std.ArrayList(u8).init(allocator);
    _ = try craft_io.encode(packet, buf.writer(), allocator, .{}, ConfigClientInformationPacket.ENCODING);
    std.debug.print("encoded {d} bytes -> {any}\n", .{ buf.items.len, buf.items });
}

pub const ConfigPluginMessagePacket = struct {
    channel: []const u8,
    data: []const u8,

    pub const Encoding = craft_io.Encoding(@This());
    pub const ENCODING: Encoding = .{
        .channel = .{ .max_items = MAX_IDENTIFIER_SIZE },
        .data = .{ .max_items = 0x100000, .length = .disabled },
    };
};

pub const KeepAlivePacket = struct { id: i64 };
pub const ConfigPingPacket = struct { id: i32 };

pub const ConfigFeatureFlagsPacket = struct {
    feature_flags: []const []const u8,

    pub const Encoding: type = craft_io.Encoding(@This());
    pub const ENCODING: Encoding = .{
        .feature_flags = .{ .items = .{ .max_items = MAX_IDENTIFIER_SIZE } },
    };
};

pub const ConfigKnownPacksPacket = struct {
    known_packs: []const KnownPack,

    pub const KnownPack = struct {
        namespace: []const u8,
        id: []const u8,
        version: []const u8,

        pub const ENCODING: craft_io.Encoding(@This()) = .{
            .namespace = .{ .max_items = MAX_IDENTIFIER_SIZE },
            .id = .{ .max_items = MAX_IDENTIFIER_SIZE },
            .version = .{ .max_items = MAX_IDENTIFIER_SIZE },
        };

        pub fn format(
            known_pack: KnownPack,
            comptime fmt: []const u8,
            options: std.fmt.FormatOptions,
            writer: anytype,
        ) !void {
            _ = fmt;
            _ = options;
            try std.fmt.format(
                writer,
                "{{.namespace = {s}, .id = {s}, .version = {s}}}",
                .{
                    known_pack.namespace,
                    known_pack.id,
                    known_pack.version,
                },
            );
        }
    };
};

pub const ConfigRegistryDataPacket = struct {
    registry_id: []const u8,
    entries: []const Entry,

    pub const ENCODING: craft_io.Encoding(@This()) = .{
        .registry_id = .{ .max_items = MAX_IDENTIFIER_SIZE },
    };

    pub const Entry = struct {
        id: []const u8,
        data: ?nbt.NamedTag,

        pub const ENCODING: craft_io.Encoding(@This()) = .{
            .id = .{ .max_items = MAX_IDENTIFIER_SIZE },
        };
    };
};

pub const ConfigUpdateTagsPacket = struct {
    registry_tags: []const Tags,

    pub const Tags = struct {
        registry_id: []const u8,
        tags: []const Tag,

        pub const ENCODING: craft_io.Encoding(@This()) = .{
            .registry_id = .{ .max_items = MAX_IDENTIFIER_SIZE },
        };
    };

    pub const Tag = struct {
        name: []const u8,
        entries: []const i32,

        pub const ENCODING: craft_io.Encoding(@This()) = .{
            .name = .{ .max_items = MAX_IDENTIFIER_SIZE },
            .entries = .{ .items = .varnum },
        };
    };
};

pub const ConfigAddResourcePackPacket = struct {
    id: UUID,
    url: []const u8,
    hash: []const u8,
    forced: bool,
    prompt_message: ?chat.Component,
};

pub const ConfigResourcePackResponsePacket = struct {
    id: UUID,
    result: enum(i32) {
        successfully_downloaded = 0,
        declined = 1,
        failed_to_download = 2,
        accepted = 3,
        downloaded = 4,
        invalid_url = 5,
        failed_to_reload = 6,
        discarded = 7,
    },

    pub const ENCODING: craft_io.Encoding(@This()) = .{
        .result = .varnum,
    };
};
