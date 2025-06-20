const std = @import("std");
const craft_io = @import("io.zig");
const Diag = @import("Diag.zig");
const chat = @import("chat.zig");
const UUID = @import("UUID.zig");
const util = @import("util.zig");
const nbt = @import("nbt.zig");

const MAX_IDENTIFIER_SIZE: usize = craft_io.MAX_IDENTIFIER_SIZE;

// state = handshake
pub const HandshakingPacket = struct {
    version: i32,
    address: []const u8,
    port: u16,
    next_state: enum(i32) {
        status = 1,
        login = 2,
        transfer = 3,

        pub const ENCODING: craft_io.Encoding(@This()) = .varnum;
    },

    const Encoding = craft_io.Encoding(@This());
    pub const ENCODING: Encoding = .{
        .version = .varnum,
        .address = .{ .max_items = 0xFF },
    };
};

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

    pub const Raw = struct {
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

pub const ProfileProperty = struct {
    name: []const u8,
    value: []const u8,
    signature: ?[]const u8,

    const Encoding = craft_io.Encoding(@This());
    pub const ENCODING: Encoding = .{
        .name = .{ .max_items = 0x40 },
        .value = .{ .max_items = MAX_IDENTIFIER_SIZE },
        .signature = .{ .max_items = 0x400 },
    };
};

pub const LoginSuccessPacket = struct {
    uuid: UUID,
    username: []const u8,
    properties: []const ProfileProperty,

    const Encoding = craft_io.Encoding(@This());
    pub const ENCODING: Encoding = .{ .username = .{ .max_items = 0x10 } };
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

    pub const ENCODING: craft_io.Encoding(@This()) = .{
        .threshold = .varnum,
    };
};

pub const LoginPluginRequestPacket = struct {
    message_id: i32,
    channel: []const u8, // identifer
    data: []const u8,

    pub const ENCODING: craft_io.Encoding(@This()) = .{
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

    pub const ENCODING: craft_io.Encoding(@This()) = .{
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

    pub const ENCODING: craft_io.Encoding(@This()) = .{
        .message_id = .varnum,
        .data = .{ .max_items = 0x100000, .length = .disabled },
    };
};

pub const CookieResponsePacket = struct {
    key: []const u8,
    payload: ?[]const u8, // optional bytes

    pub const ENCODING: craft_io.Encoding(@This()) = .{
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

        pub const ENCODING: craft_io.Encoding(@This()) = .varnum;
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

        pub const ENCODING: craft_io.Encoding(@This()) = .varnum;
    },
    enable_text_filtering: bool,
    allow_server_listings: bool,
    particle_status: enum(i32) {
        all = 0,
        decreased = 1,
        minimal = 2,

        pub const ENCODING: craft_io.Encoding(@This()) = .varnum;
    },

    pub const ENCODING: craft_io.Encoding(@This()) = .{
        .locale = .{ .max_items = 16 },
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

pub const IDSet = union(enum) {
    tagged: []const u8,
    ids: []const i32,

    pub const CraftEncoding: type = void;
    pub const ENCODING: CraftEncoding = {};

    pub fn craftEncode(
        id_set: IDSet,
        writer: anytype,
        allocator: std.mem.Allocator,
        diag: Diag,
        comptime encoding: void,
    ) !usize {
        _ = encoding;
        var bytes_written: usize = 0;
        switch (id_set) {
            .tagged => |tag_name| {
                bytes_written += try craft_io.encode(
                    @as(i32, 0),
                    writer,
                    allocator,
                    try diag.child(.{ .field = "type" }),
                    .varnum,
                );
                bytes_written += try craft_io.encode(
                    tag_name,
                    writer,
                    allocator,
                    try diag.child(.{ .field = "tag_name" }),
                    .{ .max_items = MAX_IDENTIFIER_SIZE },
                );
            },
            .ids => |id_list| {
                bytes_written += try craft_io.encode(
                    @as(i32, id_list.len + 1),
                    writer,
                    allocator,
                    try diag.child(.{ .field = "type" }),
                    .varnum,
                );
                bytes_written += try craft_io.encode(
                    id_list,
                    writer,
                    allocator,
                    try diag.child(.{ .field = "ids" }),
                    .{},
                );
            },
        }
        return bytes_written;
    }

    pub fn craftDecode(
        reader: anytype,
        arena_allocator: *std.heap.ArenaAllocator,
        diag: Diag,
        comptime encoding: CraftEncoding,
    ) !craft_io.Decoded(IDSet) {
        _ = encoding;

        var bytes_read: usize = 0;
        const typ: i32 = (try craft_io.decode(
            i32,
            reader,
            arena_allocator,
            try diag.child(.{ .field = "type" }),
            .varnum,
        )).unwrap(&bytes_read);

        if (typ == 0) {
            const tag_name = (try craft_io.decode(
                []const u8,
                reader,
                arena_allocator,
                try diag.child(.{ .field = "tag_name" }),
                .{ .max_items = MAX_IDENTIFIER_SIZE },
            )).unwrap(&bytes_read);
            return .{
                .value = .{ .tagged = tag_name },
                .bytes_read = bytes_read,
            };
        } else {
            const size: usize = @intCast(typ - 1);
            const allocator = arena_allocator.allocator();
            const id_items = try allocator.alloc(i32, size);
            errdefer allocator.free(id_items);
            for (id_items, 0..) |*item, idx| {
                item.* = (try craft_io.decode(
                    i32,
                    reader,
                    arena_allocator,
                    try diag.child(.{ .index = idx }),
                    .varnum,
                )).unwrap(&bytes_read);
            }
            return .{
                .value = .{ .ids = id_items },
                .bytes_read = bytes_read,
            };
        }
    }
};

pub const TextComponent = struct {
    nbt_data: nbt.Tag,

    pub const CraftEncoding: type = craft_io.Encoding(nbt.Tag);
    pub const CraftError: type = error{BadNbtForTextComponent};

    pub fn craftEncode(
        cmp: TextComponent,
        writer: anytype,
        allocator: std.mem.Allocator,
        diag: Diag,
        comptime encoding: CraftEncoding,
    ) !usize {
        switch (cmp.nbt_data) {
            inline .string, .compound => {
                return craft_io.encode(cmp.nbt_data, writer, allocator, diag, encoding);
            },
            else => {
                diag.report(
                    error.BadNbtForTextComponent,
                    @typeName(@This()),
                    "text components are NBT tags, but only allowed to use string and compound tag types, this is a {any}",
                    .{@as(nbt.TagType, cmp.nbt_data)},
                );
                return error.BadNbtForTextComponent;
            },
        }
    }

    pub fn craftDecode(
        reader: anytype,
        arena_allocator: *std.heap.ArenaAllocator,
        diag: Diag,
        comptime encoding: CraftEncoding,
    ) !craft_io.Decoded(TextComponent) {
        var bytes_read: usize = 0;
        const nbt_tag: nbt.Tag = (try craft_io.decode(
            nbt.Tag,
            reader,
            arena_allocator,
            diag,
            encoding,
        )).unwrap(&bytes_read);
        diag.ok(
            @typeName(nbt.Tag),
            "decode",
            bytes_read,
            "{any}",
            .{nbt_tag},
        );
        switch (nbt_tag) {
            inline .string, .compound => {
                return .{
                    .bytes_read = bytes_read,
                    .value = .{ .nbt_data = nbt_tag },
                };
            },
            else => {
                diag.report(
                    error.BadNbtForTextComponent,
                    @typeName(@This()),
                    "text components are NBT tags, but only allowed to use string and compound tag types, this is a {any}",
                    .{@as(nbt.TagType, nbt_tag)},
                );
                return error.DecodeBadData;
            },
        }
    }
};

pub const BlockPredicate = struct {
    blocks: ?IDSet,
    properties: ?[]const Property,
    nbt: ?nbt.Tag,
    data_components: []const StructuredComponent,
    partial_data_components: []const PartialDataComponentMatcher,
};

pub const PartialDataComponentMatcher = struct {
    type: enum(i32) {
        damage = 0,
        enchantments = 1,
        stored_enchantments = 2,
        potion_contents = 3,
        custom_data = 4,
        container = 5,
        bundle_contents = 6,
        firework_explosion = 7,
        fireworks = 8,
        writable_book_content = 9,
        written_book_content = 10,
        attribute_modifiers = 11,
        trim = 12,
        jukebox_playable = 13,

        pub const ENCODING: craft_io.Encoding(@This()) = .varnum;
    },
    predicate: nbt.NamedTag,
};

pub const Property = struct {
    name: []const u8,
    range: Range,

    pub const RangeType = enum(u8) {
        min_max = 0,
        exact = 1,
    };

    pub const Range = union(RangeType) {
        min_max: struct {
            min_value: []const u8,
            max_value: []const u8,
        },
        exact: struct {
            exact_value: []const u8,
        },
    };
};

pub const PotionEffect = struct {
    type_id: i32,
    details: Detail,

    pub const ENCODING: craft_io.Encoding(@This()) = .{
        .type_id = .varnum,
    };

    pub const Detail = struct {
        amplifier: i32,
        duration: i32, // todo type safe infinite
        ambient: bool,
        show_particles: bool,
        show_icon: bool,
        hidden_effect: ?*const Detail,

        pub const CraftEncoding: type = struct {
            amplifier: craft_io.Encoding(i32) = .varnum,
            duration: craft_io.Encoding(i32) = .varnum,
        };
    };
};

pub const SoundEvent = struct {
    sound_name: []const u8,
    fixed_range: ?f32,

    pub const ENCODING: craft_io.Encoding(@This()) = .{
        .sound_name = .{ .max_items = MAX_IDENTIFIER_SIZE },
    };
};

pub const ConsumeEffectType = enum(i32) {
    apply_effects = 0,
    remove_effects = 1,
    clear_all_effects = 2,
    teleport_randomly = 3,
    play_sound = 4,

    pub const ENCODING: craft_io.Encoding(@This()) = .varnum;
};

pub const ConsumeEffect = union(ConsumeEffectType) {
    apply_effects: struct {
        effects: []const PotionEffect,
        probability: f32,
    },
    remove_effects: struct {
        effects: IDSet,
    },
    clear_all_effects,
    teleport_randomly: struct {
        diameter: f32,
    },
    play_sound: struct {
        sound: SoundEvent,
    },
};

pub const TrimMaterial = struct {
    suffix: []const u8,
    overrides: []const struct {
        armor_material_type: []const u8,
        overidden_asset_name: []const u8,

        pub const ENCODING: craft_io.Encoding(@This()) = .{
            .armor_material_type = .{ .max_items = MAX_IDENTIFIER_SIZE },
        };
    },
    description: TextComponent,
};

pub const TrimPattern = struct {
    asset_name: []const u8,
    template_item: i32,
    description: TextComponent,
    decal: bool,

    pub const ENCODING: craft_io.Encoding(@This()) = .{
        .template_item = .varnum,
    };
};

pub const Instrument = struct {
    sound_event: craft_io.IdOr(SoundEvent),
    sound_range: f32,
    range: f32,
    description: TextComponent,
};

pub const JukeboxSong = struct {
    sound_event: craft_io.IdOr(SoundEvent),
    description: TextComponent,
    duration: f32,
    output: i32,

    pub const ENCODING: craft_io.Encoding(@This()) = .{
        .output = .varnum,
    };
};

pub const FireworkExplosion = struct {
    shape: Shape,
    colors: []const i32,
    fade_colors: []const i32,
    has_trail: bool,
    has_twinkle: bool,

    pub const ENCODING: craft_io.Encoding(@This()) = .{
        .colors = .{ .items = .varnum },
        .fade_colors = .{ .items = .varnum },
    };

    pub const Shape = enum(i32) {
        small_ball = 0,
        large_ball = 1,
        star = 2,
        creeper = 3,
        burst = 4,

        pub const ENCODING: craft_io.Encoding(@This()) = .varnum;
    };
};

pub const DyeColor = enum(i32) {
    white = 0,
    orange = 1,
    magenta = 2,
    light_blue = 3,
    yellow = 4,
    lime = 5,
    pink = 6,
    gray = 7,
    light_gray = 8,
    cyan = 9,
    purple = 10,
    blue = 11,
    brown = 12,
    green = 13,
    red = 14,
    black = 15,

    pub const ENCODING: craft_io.Encoding(@This()) = .varnum;
};

pub const VariantSelection = struct {
    variant: i32,

    pub const ENCODING: craft_io.Encoding(@This()) = .{
        .variant = .varnum,
    };
};

pub const PaintingVariant = struct {
    width: i32,
    height: i32,
    asset_id: []const u8,
    title: ?TextComponent,
    author: ?TextComponent,

    pub const ENCODING: craft_io.Encoding(@This()) = .{
        .asset_id = .{ .max_items = MAX_IDENTIFIER_SIZE },
    };
};

pub const StructuredComponentType = enum(i32) {
    custom_data = 0,
    max_stack_size = 1,
    max_damage = 2,
    damage = 3,
    unbreakable = 4,
    custom_name = 5,
    item_name = 6,
    item_model = 7,
    lore = 8,
    rarity = 9,
    enchantments = 10,
    can_place_on = 11,
    can_break = 12,
    attribute_modifiers = 13,
    custom_model_data = 14,
    tooltip_display = 15,
    repair_cost = 16,
    creative_slot_block = 17,
    enchantment_glint_override = 18,
    intangible_projectile = 19,
    food = 20,
    consumable = 21,
    use_remainder = 22,
    use_cooldown = 23,
    damage_resistant = 24,
    tool = 25,
    weapon = 26,
    enchantable = 27,
    equippable = 28,
    repairable = 29,
    glider = 30,
    tooltip_style = 31,
    death_protection = 32,
    blocks_attacks = 33,
    stored_enchantments = 34,
    dyed_color = 35,
    map_color = 36,
    map_id = 37,
    decorations = 38,
    map_post_processing = 39,
    charged_projectiles = 40,
    bundle_contents = 41,
    potion_contents = 42,
    potion_duration_scale = 43,
    suspicious_stew_effects = 44,
    writable_book_content = 45,
    written_book_content = 46,
    trim = 47,
    debug_stick_state = 48,
    entity_data = 49,
    bucket_entity_data = 50,
    block_entity_data = 51,
    instrument = 52,
    provides_trim_material = 53,
    ominous_bottle_amplifier = 54,
    jukebox_playable = 55,
    provides_banner_patterns = 56,
    recipes = 57,
    lodestone_tracker = 58,
    firework_explosion = 59,
    fireworks = 60,
    profile = 61,
    note_block_sound = 62,
    banner_patterns = 63,
    base_color = 64,
    pot_decorations = 65,
    container = 66,
    block_state = 67,
    bees = 68,
    lock = 69,
    container_loot = 70,
    break_sound = 71,
    villager_variant = 72,
    wolf_variant = 73,
    wolf_sound_variant = 74,
    wolf_collar = 75,
    fox_variant = 76,
    salmon_size = 77,
    parrot_variant = 78,
    tropical_fish_pattern = 79,
    tropical_fish_base_color = 80,
    tropical_fish_pattern_color = 81,
    mooshroom_variant = 82,
    rabbit_variant = 83,
    pig_variant = 84,
    cow_variant = 85,
    chicken_variant = 86,
    frog_variant = 87,
    horse_variant = 88,
    painting_variant = 89,
    llama_variant = 90,
    axolotl_variant = 91,
    cat_variant = 92,
    cat_collar = 93,
    sheep_color = 94,
    shulker_color = 95,

    pub const ENCODING: craft_io.Encoding(@This()) = .varnum;
};

pub const BookPage = struct {
    raw_content: TextComponent,
    filtered_content: ?TextComponent,
};

pub fn IdentifierOr(
    comptime AltType: type,
    comptime alt_default_encoding: craft_io.Encoding(AltType),
) type {
    const M = enum(i8) {
        identifier = 0,
        payload = 1,
    };

    return union(M) {
        identifier: []const u8,
        payload: AltType,

        pub const Mode = M;
        pub const ENCODING: craft_io.Encoding(@This()) = .{
            .fields = .{
                .identifier = .{ .max_items = MAX_IDENTIFIER_SIZE },
                .payload = alt_default_encoding,
            },
        };
    };
}

pub const StructuredComponent = union(StructuredComponentType) {
    custom_data: nbt.NamedTag,
    max_stack_size: i32,
    max_damage: i32,
    damage: i32,
    unbreakable,
    custom_name: TextComponent,
    item_name: TextComponent,
    item_model: []const u8,
    lore: struct {
        lines: []const TextComponent,
    },
    rarity: enum(i32) {
        common = 0,
        uncommon = 1,
        rare = 2,
        epic = 3,

        pub const ENCODING: craft_io.Encoding(@This()) = .varnum;
    },
    enchantments: []const struct {
        enchantment_id: i32,
        level: i32,

        pub const ENCODING: craft_io.Encoding(@This()) = .{
            .enchantment_id = .varnum,
            .level = .varnum,
        };
    },
    can_place_on: []const BlockPredicate,
    can_break: []const BlockPredicate,
    attribute_modifiers: []const struct {
        attribute_id: i32,
        modifier_id: []const u8,
        value: f64,
        operation: enum(i32) {
            add = 0,
            multiply_base = 1,
            multiply_total = 2,

            pub const ENCODING: craft_io.Encoding(@This()) = .varnum;
        },
        slot: enum(i32) {
            any = 0,
            main_hand = 1,
            off_hand = 2,
            hand = 3,
            feet = 4,
            legs = 5,
            chest = 6,
            head = 7,
            armor = 8,
            body = 9,

            pub const ENCODING: craft_io.Encoding(@This()) = .varnum;
        },

        pub const ENCODING: craft_io.Encoding(@This()) = .{
            .attribute_id = .varnum,
        };
    },
    custom_model_data: struct {
        floats: []const f32,
        flags: []const bool,
        strings: []const []const u8,
        colors: []const i32,
    },
    tooltip_display: struct {
        hide_tooltip: bool,
        hidden_components: []const i32,

        pub const ENCODING: craft_io.Encoding(@This()) = .{
            .hidden_components = .{ .items = .varnum },
        };
    },
    repair_cost: i32,
    creative_slot_block,
    enchantment_glint_override: struct { has_glint: bool },
    intangible_projectile: nbt.NamedTag,
    food: struct {
        nutrition: i32,
        saturation_modifier: f32,
        can_always_eat: bool,

        pub const ENCODING: craft_io.Encoding(@This()) = .{
            .nutrition = .varnum,
        };
    },
    consumable: struct {
        consume_seconds: f32,
        animation: enum(i32) {
            none = 0,
            eat = 1,
            drink = 2,
            block = 3,
            bow = 4,
            spear = 5,
            crossbow = 6,
            spyglass = 7,
            toot_horn = 8,
            brush = 9,

            pub const ENCODING: craft_io.Encoding(@This()) = .varnum;
        },
        sound: craft_io.IdOr(SoundEvent),
        has_consume_particles: bool,
        effects: []const ConsumeEffect,
    },
    use_remainder: struct {
        remainder: Slot,
    },
    use_cooldown: struct {
        seconds: f32,
        cooldown_group: ?[]const u8,

        pub const ENCODING: craft_io.Encoding(@This()) = .{
            .cooldown_group = .{ .max_items = MAX_IDENTIFIER_SIZE },
        };
    },
    damage_resistant: struct {
        types: []const u8,

        pub const ENCODING: craft_io.Encoding(@This()) = .{
            .types = .{ .max_items = MAX_IDENTIFIER_SIZE },
        };
    },
    tool: struct {
        rules: []const Rule,
        default_mining_speed: f32,
        damage_per_block: i32,

        pub const ENCODING: craft_io.Encoding(@This()) = .{
            .damage_per_block = .varnum,
        };

        pub const Rule = struct {
            blocks: IDSet,
            speed: ?f32,
            correct_drop_for_blocks: ?bool,
        };
    },
    weapon: struct {
        damage_per_attack: i32,
        disable_blocking_for: f32,

        pub const ENCODING: craft_io.Encoding(@This()) = .{
            .damage_per_attack = .varnum,
        };
    },
    enchantable: i32,
    equippable: struct {
        slot: enum(i32) {
            main_hand = 0,
            feet = 1,
            legs = 2,
            chest = 3,
            head = 4,
            offhand = 5,
            body = 6,

            pub const ENCODING: craft_io.Encoding(@This()) = .varnum;
        },
        equip_sound: craft_io.IdOr(SoundEvent),
        model: ?[]const u8,
        camera_overlay: ?[]const u8,
        allowed_entities: ?IDSet,
        dispensable: bool,
        swappable: bool,
        damage_on_hurt: bool,

        pub const ENCODING: craft_io.Encoding(@This()) = .{
            .model = .{ .max_items = MAX_IDENTIFIER_SIZE },
            .camera_overlay = .{ .max_items = MAX_IDENTIFIER_SIZE },
        };
    },
    repairable: IDSet,
    glider,
    tooltip_style: struct {
        style: []const u8,

        pub const ENCODING: craft_io.Encoding(@This()) = .{
            .style = .{ .max_items = MAX_IDENTIFIER_SIZE },
        };
    },
    death_protection: []const ConsumeEffect,
    blocks_attacks: struct {
        block_delay_seconds: f32,
        disable_cooldown_scale: f32,
        damage_reductions: []const struct {
            horizontal_blocking_angle: f32,
            type: ?IDSet,
            base: f32,
            factor: f32,
        },
        item_damage_threshold: f32,
        item_damage_base: f32,
        item_damage_factor: f32,
        bypassed_by: ?[]const u8,
        block_sound: ?craft_io.IdOr(SoundEvent),
        disable_sound: ?craft_io.IdOr(SoundEvent),
    },
    stored_enchantments: []const struct {
        type_id: i32,
        level: i32,

        pub const ENCODING: craft_io.Encoding(@This()) = .{
            .type_id = .varnum,
            .level = .varnum,
        };
    },
    dyed_color: struct { color: i32 },
    map_color: struct { color: i32 },
    map_id: struct {
        id: i32,

        pub const ENCODING: craft_io.Encoding(@This()) = .{ .id = .varnum };
    },
    decorations: nbt.NamedTag,
    map_post_processing: enum(i32) {
        lock = 0,
        scale = 1,

        pub const ENCODING: craft_io.Encoding(@This()) = .varnum;
    },
    charged_projectiles: []const Slot,
    bundle_contents: []const Slot,
    potion_contents: struct {
        potion_id: ?i32,
        custom_color: ?i32,
        custom_effects: []const PotionEffect,
        custom_name: []const u8,

        pub const ENCODING: craft_io.Encoding(@This()) = .{
            .potion_id = .varnum,
            .custom_color = .varnum,
        };
    },
    potion_duration_scale: struct {
        effect_multiplier: f32,
    },
    suspicious_stew_effects: []const struct {
        type_id: i32,
        duration: i32,

        pub const ENCODING: craft_io.Encoding(@This()) = .{
            .type_id = .varnum,
            .duration = .varnum,
        };
    },
    writable_book_content: struct {
        pages: []const BookPage,
    },
    written_book_content: struct {
        raw_title: []const u8,
        filtered_title: ?[]const u8,
        author: []const u8,
        generation: i32,
        pages: []const BookPage,
        resolved: bool,

        pub const ENCODING: craft_io.Encoding(@This()) = .{
            .raw_title = .{ .max_items = 32 },
            .filtered_title = .{ .max_items = 32 },
            .generation = .varnum,
        };
    },
    trim: struct {
        material: craft_io.IdOr(TrimMaterial),
        pattern: craft_io.IdOr(TrimPattern),
    },
    debug_stick_state: nbt.NamedTag,
    entity_data: nbt.NamedTag,
    bucket_entity_data: nbt.NamedTag,
    block_entity_data: nbt.NamedTag,
    instrument: craft_io.IdOr(Instrument),
    provides_trim_material: IdentifierOr(craft_io.IdOr(TrimMaterial), .{}),
    ominous_bottle_amplifier: struct {
        amplifier: i32,

        pub const ENCODING: craft_io.Encoding(@This()) = .{
            .amplifier = .varnum,
        };
    },
    jukebox_playable: IdentifierOr(craft_io.IdOr(JukeboxSong), .{}),
    provides_banner_patterns: struct {
        key: []const u8,

        pub const ENCODING: craft_io.Encoding(@This()) = .{
            .key = .{ .max_items = MAX_IDENTIFIER_SIZE },
        };
    },
    recipes: nbt.NamedTag,
    lodestone_tracker: struct {
        global_position: ?struct {
            dimension: []const u8,
            position: craft_io.Position,

            pub const ENCODING: craft_io.Encoding(@This()) = .{
                .dimension = .{ .max_items = MAX_IDENTIFIER_SIZE },
            };
        },
        tracked: bool,
    },
    firework_explosion: FireworkExplosion,
    fireworks: struct {
        flight_duration: i32,
        explosions: []const FireworkExplosion,
    },
    profile: struct {
        name: ?[]const u8,
        uuid: ?UUID,
        properties: []const ProfileProperty,

        pub const ENCODING: craft_io.Encoding(@This()) = .{
            .name = .{ .max_items = 16 },
        };
    },
    note_block_sound: struct {
        sound: []const u8,

        pub const ENCODING: craft_io.Encoding(@This()) = .{
            .sound = .{ .max_items = MAX_IDENTIFIER_SIZE },
        };
    },
    banner_patterns: struct {
        layers: []const struct {
            // FIXME this is offset by 1 if we decode a pattern type non-0
            pattern: craft_io.IdOr(struct {
                asset_id: []const u8,
                translation_key: []const u8,

                pub const ENCODING: craft_io.Encoding(@This()) = .{
                    .asset_id = .{ .max_items = MAX_IDENTIFIER_SIZE },
                };
            }),
            color: DyeColor,
        },
    },
    base_color: DyeColor,
    pot_decorations: struct {
        decorations: []const i32,

        pub const ENCODING: craft_io.Encoding(@This()) = .{
            .decorations = .{ .max_items = 4, .items = .varnum },
        };
    },
    container: struct {
        items: []const Slot,

        pub const ENCODING: craft_io.Encoding(@This()) = .{
            .items = .{ .max_items = 256 },
        };
    },
    block_state: []const struct {
        name: []const u8,
        value: []const u8,
    },
    bees: []const struct {
        entity_data: nbt.NamedTag,
        ticks_in_hive: i32,
        min_ticks_in_hive: i32,

        pub const ENCODING: craft_io.Encoding(@This()) = .{
            .ticks_in_hive = .varnum,
            .min_ticks_in_hive = .varnum,
        };
    },
    lock: TextComponent, // FIXME doesn't match wiki, but is correct
    container_loot: nbt.NamedTag,
    break_sound: craft_io.IdOr(SoundEvent),
    villager_variant: VariantSelection,
    wolf_variant: VariantSelection,
    wolf_sound_variant: VariantSelection,
    wolf_collar: DyeColor,
    fox_variant: enum(i32) {
        red = 0,
        snow = 1,

        pub const ENCODING: craft_io.Encoding(@This()) = .varnum;
    },
    salmon_size: enum(i32) {
        small = 0,
        medium = 1,
        large = 2,

        pub const ENCODING: craft_io.Encoding(@This()) = .varnum;
    },
    parrot_variant: VariantSelection,
    tropical_fish_pattern: enum(i32) {
        kob = 0,
        sunstreak = 1,
        snooper = 2,
        dasher = 3,
        brinely = 4,
        spotty = 5,
        flopper = 6,
        stripey = 7,
        glitter = 8,
        blockfish = 9,
        betty = 10,
        clayfish = 11,

        pub const ENCODING: craft_io.Encoding(@This()) = .varnum;
    },
    tropical_fish_base_color: DyeColor,
    tropical_fish_pattern_color: DyeColor,
    mooshroom_variant: enum(i32) {
        red = 0,
        brown = 1,

        pub const ENCODING: craft_io.Encoding(@This()) = .varnum;
    },
    rabbit_variant: enum(i32) {
        brown = 0,
        white = 1,
        black = 2,
        white_splotched = 3,
        gold = 4,
        salt = 5,
        evil = 6,

        pub const ENCODING: craft_io.Encoding(@This()) = .varnum;
    },
    pig_variant: VariantSelection,
    cow_variant: VariantSelection,
    chicken_variant: IdentifierOr(i32, .varnum),
    frog_variant: VariantSelection,
    horse_variant: enum(i32) {
        white = 0,
        creamy = 1,
        chestnut = 2,
        brown = 3,
        black = 4,
        gray = 5,
        dark_brown = 6,

        pub const ENCODING: craft_io.Encoding(@This()) = .varnum;
    },
    painting_variant: PaintingVariant,
    llama_variant: enum(i32) {
        creamy = 0,
        white = 1,
        brown = 2,
        gray = 3,

        pub const ENCODING: craft_io.Encoding(@This()) = .varnum;
    },
    axolotl_variant: enum(i32) {
        lucy = 0,
        wild = 1,
        gold = 2,
        cyan = 3,
        blue = 4,

        pub const ENCODING: craft_io.Encoding(@This()) = .varnum;
    },
    cat_variant: VariantSelection,
    cat_collar: DyeColor,
    sheep_color: DyeColor,
    shulker_color: DyeColor,

    pub const CraftEncoding: type = struct {
        tag: craft_io.Encoding(i32) = .varnum,
        fields: struct {
            max_stack_size: craft_io.Encoding(i32) = .varnum,
            max_damage: craft_io.Encoding(i32) = .varnum,
            damage: craft_io.Encoding(i32) = .varnum,
            repair_cost: craft_io.Encoding(i32) = .varnum,
            enchantable: craft_io.Encoding(i32) = .varnum,
        } = .{},
    };

    pub const ENCODING: CraftEncoding = .{};
};

pub const Slot = struct {
    count: i32,
    data: ?SlotData,

    pub const CraftEncoding: type = void;

    pub fn craftEncode(
        slot: Slot,
        writer: anytype,
        allocator: std.mem.Allocator,
        diag: Diag,
        comptime encoding: CraftEncoding,
    ) !usize {
        _ = encoding;
        var bytes_written: usize = 0;
        bytes_written += try craft_io.encode(
            slot.count,
            writer,
            allocator,
            try diag.child(.{ .field = "count" }),
            .varnum,
        );
        if (slot.count > 0) {
            if (slot.data) |payload| {
                bytes_written += try craft_io.encode(
                    payload,
                    writer,
                    allocator,
                    diag,
                    {},
                );
            } else {
                diag.report(
                    error.NonEmptySlotHasData,
                    @typeName(@This()),
                    "slot data has count of {d} but doesn't have associated data",
                    .{slot.count},
                );
                return error.NonEmptySlotHasData;
            }
        }
        return bytes_written;
    }

    pub fn craftDecode(
        reader: anytype,
        arena_allocator: *std.heap.ArenaAllocator,
        diag: Diag,
        comptime encoding: CraftEncoding,
    ) !craft_io.Decoded(Slot) {
        _ = encoding;
        var bytes_read: usize = 0;
        var out: Slot = undefined;
        out.count = (try craft_io.decode(
            i32,
            reader,
            arena_allocator,
            try diag.child(.{ .field = "count" }),
            .varnum,
        )).unwrap(&bytes_read);
        if (out.count == 0) {
            out.data = null;
        } else {
            out.data = (try craft_io.decode(
                SlotData,
                reader,
                arena_allocator,
                diag,
                {},
            )).unwrap(&bytes_read);
        }
        return .{
            .value = out,
            .bytes_read = bytes_read,
        };
    }
};

pub const SlotData = struct {
    item_id: i32,
    components_to_add: []const StructuredComponent,
    components_to_remove: []const StructuredComponentType,

    pub const CraftEncoding: type = void;

    pub fn craftEncode(
        slot: SlotData,
        writer: anytype,
        allocator: std.mem.Allocator,
        diag: Diag,
        comptime encoding: CraftEncoding,
    ) !usize {
        _ = encoding;
        var bytes_written: usize = 0;
        bytes_written += try craft_io.encode(
            slot.item_id,
            writer,
            allocator,
            try diag.child(.{ .field = "item_id" }),
            .varnum,
        );

        bytes_written += try craft_io.encode(
            slot.components_to_add.len,
            writer,
            allocator,
            try (try diag.child(.{ .field = "components_to_add" })).child(.length_prefix),
            .varnum,
        );

        bytes_written += try craft_io.encode(
            slot.components_to_remove.len,
            writer,
            allocator,
            try (try diag.child(.{ .field = "components_to_remove" })).child(.length_prefix),
            .varnum,
        );

        bytes_written += try craft_io.encode(
            slot.components_to_add,
            writer,
            allocator,
            try diag.child(.{ .field = "components_to_add" }),
            .{ .length = .disabled, .items = .{} },
        );

        bytes_written += try craft_io.encode(
            slot.components_to_remove,
            writer,
            allocator,
            try diag.child(.{ .field = "components_to_remove" }),
            .{ .length = .disabled, .items = .{} },
        );

        return bytes_written;
    }

    pub fn craftDecode(
        reader: anytype,
        arena_allocator: *std.heap.ArenaAllocator,
        diag: Diag,
        comptime encoding: CraftEncoding,
    ) !craft_io.Decoded(SlotData) {
        _ = encoding;
        var bytes_read: usize = 0;
        const item_id: i32 = (try craft_io.decode(
            i32,
            reader,
            arena_allocator,
            try diag.child(.{ .field = "item_id" }),
            .varnum,
        )).unwrap(&bytes_read);

        const num_components_to_add = (try craft_io.decode(
            i32,
            reader,
            arena_allocator,
            try (try diag.child(.{ .field = "components_to_add" })).child(.length_prefix),
            .varnum,
        )).unwrap(&bytes_read);

        const num_components_to_remove = (try craft_io.decode(
            i32,
            reader,
            arena_allocator,
            try (try diag.child(.{ .field = "components_to_remove" })).child(.length_prefix),
            .varnum,
        )).unwrap(&bytes_read);

        var out: @This() = undefined;
        out.item_id = item_id;

        const allocator = arena_allocator.allocator();
        if (num_components_to_add == 0) {
            out.components_to_add = &.{};
        } else {
            const components_to_add_buf = try allocator.alloc(StructuredComponent, @intCast(num_components_to_add));
            errdefer allocator.free(components_to_add_buf);

            for (components_to_add_buf, 0..) |*item, idx| {
                item.* = (try craft_io.decode(
                    StructuredComponent,
                    reader,
                    arena_allocator,
                    try (try diag.child(.{ .field = "components_to_add" })).child(.{ .index = idx }),
                    craft_io.defaultEncoding(StructuredComponent),
                )).unwrap(&bytes_read);
            }
            out.components_to_add = components_to_add_buf;
        }

        if (num_components_to_remove == 0) {
            out.components_to_remove = &.{};
        } else {
            const components_to_remove_buf = try allocator.alloc(StructuredComponentType, @intCast(num_components_to_add));
            errdefer allocator.free(components_to_remove_buf);

            for (components_to_remove_buf, 0..) |*item, idx| {
                item.* = (try craft_io.decode(
                    StructuredComponentType,
                    reader,
                    arena_allocator,
                    try (try diag.child(.{ .field = "components_to_remove" })).child(.{ .index = idx }),
                    craft_io.defaultEncoding(StructuredComponentType),
                )).unwrap(&bytes_read);
            }
            out.components_to_remove = components_to_remove_buf;
        }

        return .{
            .value = out,
            .bytes_read = bytes_read,
        };
    }
};

pub const SlotDisplayType = enum(i32) {
    empty = 0,
    any_fuel = 1,
    item = 2,
    item_stack = 3,
    tag = 4,
    smithing_trim = 5,
    with_remainder = 6,
    composite = 7,

    pub const ENCODING: craft_io.Encoding(@This()) = .varnum;
};

pub const SlotDisplay = union(SlotDisplayType) {
    empty,
    any_fuel,
    item: struct {
        type_id: i32,

        pub const ENCODING: craft_io.Encoding(@This()) = .{
            .type_id = .varnum,
        };
    },
    item_stack: Slot,
    tag: struct {
        tag: []const u8,

        pub const ENCODING: craft_io.Encoding(@This()) = .{
            .tag = .{ .max_items = MAX_IDENTIFIER_SIZE },
        };
    },
    smithing_trim: struct {
        base: *const SlotDisplay,
        material: *const SlotDisplay,
        pattern: *const SlotDisplay,
    },
    with_remainder: struct {
        ingredient: *const SlotDisplay,
        remainder: *const SlotDisplay,
    },
    composite: struct {
        options: []const SlotDisplay,
    },

    pub const CraftEncoding = struct {
        tag: craft_io.Encoding(SlotDisplayType) = craft_io.defaultEncoding(SlotDisplayType),
    };
};

pub const PlayClientboundPacketID = enum(i32) {
    bundle_delimiter = 0x00,
    spawn_entity = 0x01,
    block_update = 0x08,
    change_difficulty = 0x0A,
    set_container_content = 0x12,
    set_container_slot = 0x14,
    damage_event = 0x19,
    disconnect = 0x1C,
    entity_event = 0x1E,
    teleport_entity = 0x1F,
    game_event = 0x22,
    initialize_world_border = 0x25,
    keep_alive = 0x26,
    chunk_data = 0x27,
    world_event = 0x28,
    update_light = 0x2A,
    login = 0x2B,
    map_data = 0x2C,
    move_entity_position = 0x2E,
    update_entity_position_and_rotation = 0x2F,
    update_entity_rotation = 0x31,
    player_abilities = 0x39,
    player_chat = 0x3A,
    player_info_update = 0x3F,
    synchronize_player_position = 0x41,
    recipe_book_add = 0x43,
    recipe_book_settings = 0x45,
    remove_entities = 0x46,
    set_head_rotation = 0x4C,
    update_section_blocks = 0x4D,
    server_data = 0x4F,
    set_center_chunk = 0x57,
    set_render_distance = 0x58,
    set_default_spawn_position = 0x5A,
    set_entity_metadata = 0x5C,
    set_entity_velocity = 0x5E,
    set_equipment = 0x5F,
    set_experience = 0x60,
    set_health = 0x61,
    set_held_item = 0x62,
    set_simulation_distance = 0x68,
    update_time = 0x6A,
    sound_effect = 0x6E,
    system_chat_message = 0x72,
    set_ticking_state = 0x78,
    step_tick = 0x79,
    update_advancements = 0x7B,
    update_attributes = 0x7C,
    update_recipes = 0x7E,

    pub fn Payload(comptime id: PlayClientboundPacketID) type {
        return switch (id) {
            .bundle_delimiter => PlayBundleDelimiterPacket,
            .spawn_entity => PlaySpawnEntityPacket,
            .block_update => PlayBlockUpdatePacket,
            .change_difficulty => PlayChangeDifficultyPacket,
            .set_container_content => PlaySetContainerContentPacket,
            .set_container_slot => PlaySetContainerSlotPacket,
            .damage_event => PlayDamageEventPacket,
            .disconnect => PlayDisconnectPacket,
            .entity_event => PlayEntityEventPacket,
            .teleport_entity => PlayTeleportEntityPacket,
            .game_event => PlayGameEventPacket,
            .initialize_world_border => PlayInitializeWorldBorderPacket,
            .keep_alive => KeepAlivePacket,
            .chunk_data => PlayChunkDataWithLightPacket,
            .world_event => PlayWorldEventPacket,
            .update_light => PlayUpdateLightPacket,
            .login => PlayLoginPacket,
            .map_data => PlayMapDataPacket,
            .move_entity_position => PlayMoveEntityPositionPacket,
            .update_entity_position_and_rotation => PlayUpdateEntityPositionAndRotationPacket,
            .update_entity_rotation => PlayUpdateEntityRotationPacket,
            .player_abilities => PlayPlayerAbilitiesPacket,
            .player_chat => PlayPlayerChatMessagePacket,
            .player_info_update => PlayPlayerInfoUpdatePacket,
            .synchronize_player_position => PlaySynchronizePlayerPositionPacket,
            .recipe_book_add => PlayRecipeBookAddPacket,
            .recipe_book_settings => PlayRecipeBookSettingsPacket,
            .remove_entities => PlayRemoveEntitiesPacket,
            .set_head_rotation => PlaySetHeadRotationPacket,
            .update_section_blocks => PlayUpdateSectionBlocksPacket,
            .server_data => PlayServerDataPacket,
            .set_center_chunk => PlaySetCenterChunkPacket,
            .set_render_distance => PlaySetRenderDistancePacket,
            .set_default_spawn_position => PlaySetDefaultSpawnPositionPacket,
            .set_entity_metadata => PlaySetEntityMetadataPacket,
            .set_entity_velocity => PlaySetEntityVelocityPacket,
            .set_equipment => PlaySetEquipmentPacket,
            .set_experience => PlaySetExperiencePacket,
            .set_health => PlaySetHealthPacket,
            .set_held_item => PlaySetHeldItemPacket,
            .set_simulation_distance => PlaySetSimulationDistancePacket,
            .update_time => PlayUpdateTimePacket,
            .sound_effect => PlaySoundEffectPacket,
            .system_chat_message => PlaySystemChatMessagePacket,
            .set_ticking_state => PlaySetTickingStatePacket,
            .step_tick => PlayStepTickPacket,
            .update_advancements => PlayUpdateAdvancementsPacket,
            .update_attributes => PlayUpdateAttributesPacket,
            .update_recipes => PlayUpdateRecipesPacket,
        };
    }

    pub fn isValidPacketId(id: i32) bool {
        return id <= 0x82 and id >= 0x00;
    }
};

pub const PlayBundleDelimiterPacket = struct {};

pub const PlayLoginPacket = struct {
    entity_id: i32,
    is_hardcore: bool,
    dimension_names: []const []const u8,
    max_players: i32, // ignored
    view_distance: i32,
    simulation_distance: i32,
    reduced_debug_info: bool,
    enable_respawn_screen: bool,
    do_limited_crafting: bool,
    dimension_type: i32, // refers to an ID set in the minecraft:dimension registry
    dimension_name: []const u8,
    hashed_seed: i64,
    game_mode: GameMode,
    previous_game_mode: PreviousGameMode,
    is_debug: bool,
    is_flat: bool,
    death_location: ?struct {
        dimension: []const u8,
        location: craft_io.Position,

        pub const ENCODING: craft_io.Encoding(@This()) = .{
            .dimension = .{ .max_items = MAX_IDENTIFIER_SIZE },
        };
    },
    portal_cooldown: i32,
    sea_level: i32,
    enforces_secure_chat: bool,

    pub const ENCODING: craft_io.Encoding(@This()) = .{
        .dimension_names = .{ .items = .{ .max_items = MAX_IDENTIFIER_SIZE } },
        .max_players = .varnum,
        .view_distance = .varnum,
        .simulation_distance = .varnum,
        .dimension_type = .varnum,
        .portal_cooldown = .varnum,
        .sea_level = .varnum,
    };

    pub const GameMode = enum(u8) {
        survival = 0,
        creative = 1,
        adventure = 2,
        spectator = 3,
    };

    pub const PreviousGameMode = enum(i8) {
        undefined = -1,
        survival = 0,
        creative = 1,
        adventure = 2,
        spectator = 3,

        pub fn toGameMode(prev_gm: PreviousGameMode) ?GameMode {
            return switch (prev_gm) {
                .undefined => null,
                else => @enumFromInt(@intFromEnum(prev_gm)),
            };
        }
    };
};

pub const PlayMapDataPacket = struct {
    map_id: i32,
    scale: i8,
    locked: bool,
    icons: ?[]const Icon,
    color_patch: ColorPatch,

    pub const ENCODING: craft_io.Encoding(@This()) = .{
        .map_id = .varnum,
    };

    pub const Icon = struct {
        type: enum(i32) {
            white_arrow = 0,
            green_arrow = 1,
            red_arrow = 2,
            blue_arrow = 3,
            white_cross = 4,
            red_pointer = 5,
            white_circle = 6,
            small_white_circle = 7,
            mansion = 8,
            monument = 9,
            white_banner = 10,
            orange_banner = 11,
            magenta_banner = 12,
            light_blue_banner = 13,
            yellow_banner = 14,
            lime_banner = 15,
            pink_banner = 16,
            gray_banner = 17,
            light_gray_banner = 18,
            cyan_banner = 19,
            purple_banner = 20,
            blue_banner = 21,
            brown_banner = 22,
            green_banner = 23,
            red_banner = 24,
            black_banner = 25,
            treasure_marker = 26,
            desert_village = 27,
            plains_village = 28,
            savanna_village = 29,
            snowy_village = 30,
            taiga_village = 31,
            jungle_temple = 32,
            swamp_hut = 33,
            trial_chambers = 34,
        },
        x: i8,
        z: i8,
        direction: i8,
        display_name: ?chat.Component,

        pub const ENCODING: craft_io.Encoding(@This()) = .{
            .type = .varnum,
        };
    };

    pub const ColorPatchData = struct {
        columns: u8,
        rows: u8,
        x: u8,
        z: u8,
        data: []const u8,
    };

    pub const ColorPatch = struct {
        data: ?ColorPatchData,

        pub const CraftEncoding: type = void;
        pub const ENCODING: CraftEncoding = {};

        pub fn craftEncode(
            patches: ColorPatch,
            writer: anytype,
            allocator: std.mem.Allocator,
            diag: Diag,
            comptime encoding: CraftEncoding,
        ) !usize {
            _ = encoding;

            if (patches.data) |inner| {
                return craft_io.encode(inner, writer, allocator, diag, .{});
            } else {
                return craft_io.encode(@as(u8, 0), writer, allocator, diag, {});
            }
        }

        pub fn craftDecode(
            reader: anytype,
            allocator: *std.heap.ArenaAllocator,
            diag: Diag,
            comptime encoding: CraftEncoding,
        ) !craft_io.Decoded(ColorPatch) {
            _ = encoding;

            var bytes_read: usize = 0;
            const columns = (try craft_io.decode(
                u8,
                reader,
                allocator,
                try diag.child(.{ .field = "columns" }),
                {},
            )).unwrap(&bytes_read);
            if (columns == 0) {
                return .{
                    .value = .{ .data = null },
                    .bytes_read = bytes_read,
                };
            }

            const rows = (try craft_io.decode(
                u8,
                reader,
                allocator,
                try diag.child(.{ .field = "rows" }),
                {},
            )).unwrap(&bytes_read);
            const x = (try craft_io.decode(
                u8,
                reader,
                allocator,
                try diag.child(.{ .field = "x" }),
                {},
            )).unwrap(&bytes_read);
            const z = (try craft_io.decode(
                u8,
                reader,
                allocator,
                try diag.child(.{ .field = "z" }),
                {},
            )).unwrap(&bytes_read);
            const data = (try craft_io.decode(
                []const u8,
                reader,
                allocator,
                try diag.child(.{ .field = "data" }),
                .{},
            )).unwrap(&bytes_read);
            return .{
                .value = .{ .data = .{ .columns = columns, .rows = rows, .x = x, .z = z, .data = data } },
                .bytes_read = bytes_read,
            };
        }
    };
};

pub const PlayChangeDifficultyPacket = struct {
    difficulty: Difficulty,
    locked: bool,

    pub const Difficulty = enum(u8) { peaceful, easy, normal, hard };
};

pub const PlayPlayerAbilitiesPacket = struct {
    flags: Flags,
    flying_speed: f32,
    field_of_view_modifier: f32,

    pub const Flags = packed struct {
        invulnerable: bool,
        flying: bool,
        allow_flying: bool,
        instant_break: bool,
    };
};

pub const PlaySetHeldItemPacket = struct {
    slot: i32,

    pub const ENCODING: craft_io.Encoding(@This()) = .{ .slot = .varnum };
};

pub const PlayUpdateRecipesPacket = struct {
    property_sets: []const struct {
        property_set_id: []const u8,
        item_ids: []const i32,

        pub const ENCODING: craft_io.Encoding(@This()) = .{
            .property_set_id = .{ .max_items = MAX_IDENTIFIER_SIZE },
            .item_ids = .{ .items = .varnum },
        };
    },
    stonecutter_recipes: []const struct {
        ingredients: IDSet,
        slot_display: SlotDisplay,
    },
};

pub const PlayEntityEventPacket = struct {
    entity_id: i32,
    entity_status: u8,
};

pub const PlayRecipeBookSettingsPacket = struct {
    crafting_recipe_book: BookSettings,
    smelting_recipe_book: BookSettings,
    blast_furnace_book: BookSettings,
    smoker_recipe_book: BookSettings,

    pub const BookSettings = struct {
        open: bool,
        filter_active: bool,
    };
};

pub const RecipeDisplayType = enum(i32) {
    crafting_shapeless = 0,
    crafting_shaped = 1,
    furnace = 2,
    stonecutter = 3,
    smithing = 4,

    pub const ENCODING: craft_io.Encoding(@This()) = .varnum;
};

pub const RecipeDisplay = union(RecipeDisplayType) {
    crafting_shapeless: struct {
        ingredients: []const SlotDisplay,
        result: SlotDisplay,
        crafting_station: SlotDisplay,
    },
    crafting_shaped: struct {
        width: i32,
        height: i32,
        ingredients: []const SlotDisplay,
        result: SlotDisplay,
        crafting_station: SlotDisplay,

        pub const ENCODING: craft_io.Encoding(@This()) = .{
            .width = .varnum,
            .height = .varnum,
        };
    },
    furnace: struct {
        ingredient: SlotDisplay,
        fuel: SlotDisplay,
        crafting_station: SlotDisplay,
        cooking_time: i32,
        experience: f32,

        pub const ENCODING: craft_io.Encoding(@This()) = .{
            .cooking_time = .varnum,
        };
    },
    stonecutter: struct {
        ingredient: SlotDisplay,
        result: SlotDisplay,
        crafting_station: SlotDisplay,
    },
    smithing: struct {
        template: SlotDisplay,
        base: SlotDisplay,
        addition: SlotDisplay,
        result: SlotDisplay,
        crafting_station: SlotDisplay,
    },
};

pub const PlayRecipeBookAddPacket = struct {
    recipies: []const struct {
        recipe_id: i32,
        display: RecipeDisplay,
        group_id: i32,
        category_id: i32,
        ingredients: ?[]const IDSet,
        flags: packed struct {
            show_notification: bool,
            highlight_as_new: bool,
        },

        pub const ENCODING: craft_io.Encoding(@This()) = .{
            .recipe_id = .varnum,
            .category_id = .varnum,
            .group_id = .varnum,
        };
    },
    replace: bool,
};

pub fn Vector3(comptime Payload: type) type {
    return struct {
        x: Payload,
        y: Payload,
        z: Payload,
    };
}

pub fn PackedVector3(comptime Payload: type) type {
    return packed struct {
        x: Payload,
        y: Payload,
        z: Payload,
    };
}

pub const TeleportFlags = packed struct {
    relative_position: PackedVector3(bool),
    relative_yaw: bool,
    relative_pitch: bool,
    relative_velocity: PackedVector3(bool),
    rotate_velocity_before_applying: bool,

    pub const ENCODING: craft_io.Encoding(@This()) = .{ .as_int = .{ .bits = 32 } };
};

pub const PlaySynchronizePlayerPositionPacket = struct {
    teleport_id: i32,
    position: Vector3(f64),
    velocity: Vector3(f64),
    yaw: f32,
    pitch: f32,
    flags: TeleportFlags,

    pub const ENCODING: craft_io.Encoding(@This()) = .{
        .teleport_id = .varnum,
    };
};

pub const PlayServerDataPacket = struct {
    motd: TextComponent,
    icon: ?[]u8,
};

pub const PlaySystemChatMessagePacket = struct {
    message: TextComponent,
    overlay: bool,
};

pub const PlayUseItemPacket = struct {
    hand: enum(i32) {
        main = 0,
        off = 1,

        pub const ENCODING: craft_io.Encoding(@This()) = .varnum;
    },
    sequence: i32,
    yaw: f32,
    pitch: f32,

    pub const ENCODING: craft_io.Encoding(@This()) = .{
        .sequence = .varnum,
    };
};

pub const PlayPlayerInfoUpdatePacket = struct {
    pub const PlayerActionType = enum {
        add_player,
        initalize_chat,
        update_gamemode,
        update_listed,
        update_latency,
        update_display_name,
        update_list_priority,
        update_hat,
    };

    pub const PlayerActionsFlag = packed struct {
        add_player: bool,
        initalize_chat: bool,
        update_gamemode: bool,
        update_listed: bool,
        update_latency: bool,
        update_display_name: bool,
        update_list_priority: bool,
        update_hat: bool,

        pub fn numActive(self: PlayerActionsFlag) usize {
            var num_active: usize = 0;
            inline for (@typeInfo(@This()).@"struct".fields) |field| {
                if (@field(self, field.name)) {
                    num_active += 1;
                }
            }
            return num_active;
        }
    };

    pub const PlayerAction = union(PlayerActionType) {
        add_player: struct {
            name: []const u8,
            properties: []const ProfileProperty,
        },
        initalize_chat: ?struct {
            chat_session_id: UUID,
            public_key_expiry_time: i64,
            encoded_public_key: []const u8,
            public_key_signature: []const u8,

            pub const ENCODING: craft_io.Encoding(@This()) = .{
                .encoded_public_key = .{ .max_items = 512 },
                .public_key_signature = .{ .max_items = 4096 },
            };
        },
        update_gamemode: enum(i32) {
            survival = 0,
            creative = 1,
            adventure = 2,
            spectator = 3,
        },
        update_listed: bool,
        update_latency: i32,
        update_display_name: ?TextComponent,
        update_list_priority: i32,
        update_hat: bool,

        pub const CraftEncoding: type = craft_io.UnionFieldsEncoding(@This());
        pub const ENCODING: craft_io.Encoding(@This()) = .{
            .update_gamemode = .varnum,
            .update_latency = .varnum,
            .update_list_priority = .varnum,
        };
    };

    pub const PlayerInfoItem = struct {
        id: UUID,
        player_actions: []const PlayerAction,

        pub fn actionsFlag(self: PlayerInfoItem, diag: Diag) !PlayerActionsFlag {
            var flag: PlayerActionsFlag = @bitCast(0);
            const Counters = std.EnumArray(PlayerActionType, u8);
            var counters: Counters = .initFill(0);
            var any_dupes: bool = false;
            var action_idx: usize = 0;
            inline for (@typeInfo(PlayerActionType).@"enum".fields) |action_type_field| {
                const next_allowed_action = @as(PlayerActionType, @enumFromInt(action_type_field.value));
                if (self.player_actions.len > action_idx) {
                    if (self.player_actions[action_idx] == next_allowed_action) {
                        const counter = counters.getPtr(next_allowed_action);
                        counter.* += 1;
                        @field(flag, action_type_field.name) = true;
                        if (counter.* > 1) {
                            any_dupes = true;
                        }
                        action_idx += 1;
                    }
                }
            }
            if (any_dupes) {
                var counter_iter = counters.iterator();
                while (counter_iter.next()) |entry| {
                    const count = entry.value.*;
                    if (count > 1) {
                        diag.report(
                            error.DuplicatesPlayerInfoActionType,
                            @typeName(@This()),
                            "found {d} instances of the {s} action",
                            .{ count, @tagName(entry.key) },
                        );
                    }
                }
                return error.DuplicatesPlayerInfoActionType;
            }

            if (action_idx < self.player_actions.len) {
                diag.report(
                    error.OutOfOrderPlayerInfoActionType,
                    @typeName(@This()),
                    "player info actions were specified out of order: {any}",
                    .{self.player_actions},
                );
                return error.OutOfOrderPlayerInfoActionType;
            }

            return flag;
        }
    };

    updates: []const PlayerInfoItem,

    pub const CraftEncoding: type = void;
    pub const ENCODING: CraftEncoding = {};

    pub fn craftEncode(
        pkt: PlayPlayerInfoUpdatePacket,
        writer: anytype,
        allocator: std.mem.Allocator,
        diag: Diag,
        comptime encoding: CraftEncoding,
    ) !usize {
        _ = encoding;
        const flag_diag = try diag.child(.{ .field = "flag" });
        const actions_flag = try pkt.actionsFlag(flag_diag);
        var bytes_written: usize = 0;
        bytes_written += try craft_io.encode(
            actions_flag,
            writer,
            allocator,
            flag_diag,
            comptime craft_io.defaultEncoding(PlayerActionsFlag),
        );

        const updates_diag = try diag.child(.{ .field = "updates" });

        bytes_written += try craft_io.encode(
            @as(i32, @intCast(pkt.updates.len)),
            writer,
            allocator,
            try updates_diag.child(.length_prefix),
            .varnum,
        );

        for (pkt.updates, 0..) |item, idx_update| {
            const idx_diag = try updates_diag.child(.{ .index = idx_update });
            bytes_written += try craft_io.encode(
                item.id,
                writer,
                allocator,
                try idx_diag.child(.{ .field = "id" }),
                .{},
            );
            const actions_diag = try idx_diag.child(.{ .field = "actions" });
            for (item.player_actions, 0..) |action, idx_action| {
                const action_idx_diag = try actions_diag.child(.{ .index = idx_action });
                switch (action) {
                    inline else => |payload, tag| {
                        const field_diag = try action_idx_diag.child(.{ .field = @tagName(tag) });
                        const payload_diag = try field_diag.child(.payload);
                        const field_name = @tagName(tag);
                        const Payload: type = @FieldType(PlayerAction, field_name);
                        const PayloadEncoding: type = craft_io.Encoding(Payload);
                        const payload_encoding: PayloadEncoding = @field(PlayerAction.ENCODING, field_name);
                        bytes_written += try craft_io.encode(
                            payload,
                            writer,
                            allocator,
                            payload_diag,
                            payload_encoding,
                        );
                    },
                }
            }
        }
        return bytes_written;
    }

    pub fn craftDecode(
        reader: anytype,
        arena_allocator: *std.heap.ArenaAllocator,
        diag: Diag,
        comptime encoding: CraftEncoding,
    ) !craft_io.Decoded(PlayPlayerInfoUpdatePacket) {
        _ = encoding;
        var bytes_read: usize = 0;
        const actions_flag: PlayerActionsFlag = (try craft_io.decode(
            PlayerActionsFlag,
            reader,
            arena_allocator,
            try diag.child(.{ .field = "flag" }),
            comptime craft_io.defaultEncoding(PlayerActionsFlag),
        )).unwrap(&bytes_read);

        const updates_diag = try diag.child(.{ .field = "updates" });
        const num_updates: usize = @intCast((try craft_io.decode(
            i32,
            reader,
            arena_allocator,
            try updates_diag.child(.length_prefix),
            .varnum,
        )).unwrap(&bytes_read));
        const allocator = arena_allocator.allocator();
        const updates: []PlayerInfoItem = try allocator.alloc(PlayerInfoItem, num_updates);
        errdefer allocator.free(updates);

        for (0..num_updates) |update_idx| {
            const update_idx_diag = try updates_diag.child(.{ .index = update_idx });
            const update = &updates[update_idx];
            update.*.id = (try craft_io.decode(
                UUID,
                reader,
                arena_allocator,
                try update_idx_diag.child(.{ .field = "id" }),
                .{},
            )).unwrap(&bytes_read);

            const actions: []PlayerAction = try allocator.alloc(PlayerAction, actions_flag.numActive());
            errdefer allocator.free(actions);
            var actions_idx: usize = 0;
            const actions_diag = try update_idx_diag.child(.{ .field = "actions" });
            inline for (@typeInfo(PlayerAction).@"union".fields) |action_variant| {
                if (@field(actions_flag, action_variant.name)) {
                    const idx_diag = try actions_diag.child(.{ .index = actions_idx });
                    const field_diag = try idx_diag.child(.{ .field = action_variant.name });
                    const payload_diag = try field_diag.child(.payload);
                    const ActionPayload: type = action_variant.type;
                    const ActionPayloadEncoding: type = craft_io.Encoding(ActionPayload);
                    const action_encoding: ActionPayloadEncoding = @field(PlayerAction.ENCODING, action_variant.name);
                    actions[actions_idx] = @unionInit(PlayerAction, action_variant.name, (try craft_io.decode(
                        action_variant.type,
                        reader,
                        arena_allocator,
                        payload_diag,
                        action_encoding,
                    )).unwrap(&bytes_read));
                    actions_idx += 1;
                }
            }
            update.*.player_actions = actions;
        }

        return .{
            .value = .{ .updates = updates },
            .bytes_read = bytes_read,
        };
    }

    pub fn actionsFlag(self: PlayPlayerInfoUpdatePacket, diag: Diag) !PlayerActionsFlag {
        var flag: PlayerActionsFlag = undefined;
        var has_any_flag: bool = false;
        var any_error: bool = false;
        for (self.updates, 0..) |update_item, idx| {
            const idx_diag = try diag.child(.{ .index = idx });
            const actions_flag = try update_item.actionsFlag(idx_diag);
            if (!has_any_flag) {
                flag = actions_flag;
                has_any_flag = true;
            } else if (flag != actions_flag) {
                idx_diag.report(
                    error.InconsistentPlayerActionsFlag,
                    @typeName(@This()),
                    "list of player actions should have same flags. expected {any}, but got {any}",
                    .{ flag, actions_flag },
                );
                any_error = true;
            }
        }
        if (any_error) {
            return error.InconsistentPlayerActionsFlag;
        } else {
            return flag;
        }
    }
};

pub const PlaySetRenderDistancePacket = struct {
    view_distance: i32,

    pub const ENCODING: craft_io.Encoding(@This()) = .{
        .view_distance = .varnum,
    };
};

pub const PlaySetSimulationDistancePacket = struct {
    simulation_distance: i32,

    pub const ENCODING: craft_io.Encoding(@This()) = .{
        .simulation_distance = .varnum,
    };
};

pub const PlaySetCenterChunkPacket = struct {
    chunk_x: i32,
    chunk_z: i32,

    pub const ENCODING: craft_io.Encoding(@This()) = .{
        .chunk_x = .varnum,
        .chunk_z = .varnum,
    };
};

pub const PlayInitializeWorldBorderPacket = struct {
    x: f64,
    z: f64,
    old_diameter: f64,
    new_diameter: f64,
    speed: i64,
    portal_teleport_boundary: i32,
    warning_blocks: i32,
    warning_time: i32,

    pub const ENCODING: craft_io.Encoding(@This()) = .{
        .speed = .varnum,
        .portal_teleport_boundary = .varnum,
        .warning_blocks = .varnum,
        .warning_time = .varnum,
    };
};

pub const PlayUpdateTimePacket = struct {
    world_age: i64,
    time_of_day: i64,
    time_of_day_increasing: bool,
};

pub const PlaySetDefaultSpawnPositionPacket = struct {
    location: craft_io.Position,
    angle: f32,
};

pub const PlayGameEventPacket = struct {
    event: enum(u8) {
        no_respawn_block_available = 0,
        begin_raining = 1,
        end_raining = 2,
        change_gamemode = 3,
        win_game = 4,
        demo_event = 5,
        arrow_hit_player = 6,
        rain_level_change = 7,
        thunder_level_change = 8,
        play_pufferfish_sting_sound = 9,
        play_elder_guardian_mob_appearance = 10,
        enable_respawn_screen = 11,
        limited_crafting = 12,
        start_waiting_for_level_chunks = 13,
    },
    value: f32,
};

pub const PlaySetTickingStatePacket = struct {
    tick_rate: f32,
    is_frozen: bool,
};

pub const PlayStepTickPacket = struct {
    tick_steps: i32,

    pub const ENCODING: craft_io.Encoding(@This()) = .{
        .tick_steps = .varnum,
    };
};

pub const PlaySetContainerContentPacket = struct {
    window_id: i32,
    state_id: i32,
    slot_data: []const Slot,
    carried_item: Slot,

    pub const ENCODING: craft_io.Encoding(@This()) = .{
        .window_id = .varnum,
        .state_id = .varnum,
    };
};

pub const PlaySetContainerSlotPacket = struct {
    window_id: i32,
    state_id: i32,
    slot: i16,
    slot_data: Slot,

    pub const ENCODING: craft_io.Encoding(@This()) = .{
        .window_id = .varnum,
        .state_id = .varnum,
    };
};

pub const Heightmap = struct {
    hm_type: i32,
    data: []const i64,

    pub const ENCODING: craft_io.Encoding(@This()) = .{
        .hm_type = .varnum,
    };
};

pub const ChunkData = struct {
    heightmaps: []const Heightmap,
    raw_chunk_data: []const u8,
    block_entities: []const struct {
        xz_coordinate: packed struct {
            z: u4,
            x: u4,
        },
        y: i16,
        type_code: i32,
        data: nbt.NamedTag,

        pub const ENCODING: craft_io.Encoding(@This()) = .{
            .type_code = .varnum,
        };
    },

    pub fn format(
        data: ChunkData,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fmt;
        _ = options;
        try std.fmt.format(
            writer,
            "packets.ChunkData{{ .heightmaps = [{d} heightmaps], .chunk_data = [{d} bytes], .block_entities = {any} }}",
            .{
                data.heightmaps.len,
                data.raw_chunk_data.len,
                data.block_entities,
            },
        );
    }
};

pub const PlayChunkDataWithLightPacket = struct {
    x: i32,
    z: i32,
    chunk: ChunkData,
    raw_light_data: []const u8,

    pub const ENCODING: craft_io.Encoding(@This()) = .{
        .raw_light_data = .{ .length = .disabled },
    };

    pub fn format(
        pkt: PlayChunkDataWithLightPacket,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fmt;
        _ = options;
        try std.fmt.format(
            writer,
            "packets.PlayChunkDataWithLightPacket{{ .x = {d}, .z = {d}, .chunk = {any}, .raw_light_data = [{d} bytes] }}",
            .{
                pkt.x,
                pkt.z,
                pkt.chunk,
                pkt.raw_light_data.len,
            },
        );
    }
};

pub const PlayUpdateLightPacket = struct {
    chunk_x: i32,
    chunk_z: i32,
    raw_light_data: []const u8,

    pub const ENCODING: craft_io.Encoding(@This()) = .{
        .chunk_x = .varnum,
        .chunk_z = .varnum,
        .raw_light_data = .{ .length = .disabled },
    };

    pub fn format(
        pkt: PlayUpdateLightPacket,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fmt;
        _ = options;
        try std.fmt.format(
            writer,
            "packets.PlayUpdateLightPacket{{ .chunk_x = {d}, .chunk_z = {d}, .raw_light_data = [{d} bytes] }}",
            .{
                pkt.chunk_x,
                pkt.chunk_z,
                pkt.raw_light_data.len,
            },
        );
    }
};

pub const PlayUpdateAdvancementsPacket = struct {
    reset: bool,
    advancement_mappings: []const struct {
        key: []const u8,
        advancement: Advancement,
    },
    identifiers: []const []const u8,
    progress_mappings: []const struct {
        key: []const u8,
        progress: AdvancementProgress,
    },
    show_advancements: bool,
};

pub const Advancement = struct {
    parent_id: ?[]const u8,
    display: ?AdvancementDisplay,
    requirements: []const struct {
        any_of: []const []const u8,
    },
    sends_telemetry: bool,
};

pub const AdvancementDisplay = struct {
    title: TextComponent,
    description: TextComponent,
    icon: Slot,
    frame_type: FrameType,
    background_texture: ?[]const u8,
    show_toast: bool,
    hidden: bool,
    x: f32,
    y: f32,

    pub const FrameType = enum(i32) {
        task = 0,
        challenge = 1,
        goal = 2,

        pub const ENCODING: craft_io.Encoding(@This()) = .varnum;
    };

    const Flags = packed struct {
        has_background_texture: bool,
        show_toast: bool,
        hidden: bool,

        pub const ENCODING: craft_io.Encoding(@This()) = .{
            .as_int = .{ .bits = 32 },
        };
    };

    pub const CraftEncoding: type = void;
    pub const ENCODING: CraftEncoding = {};

    pub fn craftEncode(
        adv_display: AdvancementDisplay,
        writer: anytype,
        allocator: std.mem.Allocator,
        diag: Diag,
        comptime encoding: CraftEncoding,
    ) !usize {
        _ = encoding;
        var bytes_written: usize = 0;

        bytes_written += try craft_io.encode(
            adv_display.title,
            writer,
            allocator,
            try diag.child(.{ .field = "title" }),
            comptime craft_io.defaultEncoding(TextComponent),
        );
        bytes_written += try craft_io.encode(
            adv_display.description,
            writer,
            allocator,
            try diag.child(.{ .field = "description" }),
            comptime craft_io.defaultEncoding(TextComponent),
        );
        bytes_written += try craft_io.encode(
            adv_display.icon,
            writer,
            allocator,
            try diag.child(.{ .field = "icon" }),
            comptime craft_io.defaultEncoding(Slot),
        );
        bytes_written += try craft_io.encode(
            adv_display.frame_type,
            writer,
            allocator,
            try diag.child(.{ .field = "frame_type" }),
            comptime craft_io.defaultEncoding(FrameType),
        );

        bytes_written += try craft_io.encode(
            Flags{
                .has_background_texture = adv_display.background_texture != null,
                .show_toast = adv_display.show_toast,
                .hidden = adv_display.hidden,
            },
            writer,
            allocator,
            try diag.child(.{ .field = "flags" }),
            craft_io.defaultEncoding(Flags),
        );
        if (adv_display.background_texture) |background_texture| {
            bytes_written += try craft_io.encode(
                background_texture,
                writer,
                allocator,
                try diag.child(.{ .field = "background_texture" }),
                .{ .max_items = MAX_IDENTIFIER_SIZE },
            );
        }
        bytes_written += try craft_io.encode(
            adv_display.x,
            writer,
            allocator,
            try diag.child(.{ .field = "x" }),
            comptime craft_io.defaultEncoding(f32),
        );
        bytes_written += try craft_io.encode(
            adv_display.y,
            writer,
            allocator,
            try diag.child(.{ .field = "y" }),
            comptime craft_io.defaultEncoding(f32),
        );
        return bytes_written;
    }

    pub fn craftDecode(
        reader: anytype,
        arena_allocator: *std.heap.ArenaAllocator,
        diag: Diag,
        comptime encoding: CraftEncoding,
    ) !craft_io.Decoded(AdvancementDisplay) {
        _ = encoding;
        var bytes_read: usize = 0;

        var out: AdvancementDisplay = undefined;

        out.title = (try craft_io.decode(
            TextComponent,
            reader,
            arena_allocator,
            try diag.child(.{ .field = "title" }),
            comptime craft_io.defaultEncoding(TextComponent),
        )).unwrap(&bytes_read);
        out.description = (try craft_io.decode(
            TextComponent,
            reader,
            arena_allocator,
            try diag.child(.{ .field = "description" }),
            comptime craft_io.defaultEncoding(TextComponent),
        )).unwrap(&bytes_read);
        out.icon = (try craft_io.decode(
            Slot,
            reader,
            arena_allocator,
            try diag.child(.{ .field = "icon" }),
            comptime craft_io.defaultEncoding(Slot),
        )).unwrap(&bytes_read);
        out.frame_type = (try craft_io.decode(
            FrameType,
            reader,
            arena_allocator,
            try diag.child(.{ .field = "frame_type" }),
            comptime craft_io.defaultEncoding(FrameType),
        )).unwrap(&bytes_read);

        const flags = (try craft_io.decode(
            Flags,
            reader,
            arena_allocator,
            try diag.child(.{ .field = "flags" }),
            comptime craft_io.defaultEncoding(Flags),
        )).unwrap(&bytes_read);
        if (flags.has_background_texture) {
            out.background_texture = (try craft_io.decode(
                []const u8,
                reader,
                arena_allocator,
                try diag.child(.{ .field = "background_texture" }),
                .{ .max_items = MAX_IDENTIFIER_SIZE },
            )).unwrap(&bytes_read);
        } else {
            out.background_texture = null;
        }
        out.show_toast = flags.show_toast;
        out.hidden = flags.hidden;

        out.x = (try craft_io.decode(
            f32,
            reader,
            arena_allocator,
            try diag.child(.{ .field = "x" }),
            comptime craft_io.defaultEncoding(f32),
        )).unwrap(&bytes_read);
        out.y = (try craft_io.decode(
            f32,
            reader,
            arena_allocator,
            try diag.child(.{ .field = "y" }),
            comptime craft_io.defaultEncoding(f32),
        )).unwrap(&bytes_read);
        return .{
            .value = out,
            .bytes_read = bytes_read,
        };
    }
};

pub const AdvancementProgress = struct {
    criteria: []const struct {
        criterion_id: []const u8,
        date_of_achieving: ?i64,

        pub const ENCODING: craft_io.Encoding(@This()) = .{
            .criterion_id = .{ .max_items = MAX_IDENTIFIER_SIZE },
        };
    },
};

pub const PlaySetExperiencePacket = struct {
    experience_bar: f32,
    level: i32,
    total_experience: i32,

    pub const ENCODING: craft_io.Encoding(@This()) = .{
        .level = .varnum,
        .total_experience = .varnum,
    };
};

pub const PlaySetHealthPacket = struct {
    health: f32,
    food: i32,
    food_saturation: f32,

    pub const ENCODING: craft_io.Encoding(@This()) = .{
        .food = .varnum,
    };
};

pub const PlaySoundEffectPacket = struct {
    sound_event: craft_io.IdOr(SoundEvent),
    category: i32,
    position: struct {
        x: i32,
        y: i32,
        z: i32,
    },
    volume: f32,
    pitch: f32,
    seed: i64,

    pub const ENCODING: craft_io.Encoding(@This()) = .{
        .category = .varnum,
    };
};

pub const PlayMoveEntityPositionPacket = struct {
    entity_id: i32,
    delta: Vector3(i16),
    on_ground: bool,

    pub const ENCODING: craft_io.Encoding(@This()) = .{
        .entity_id = .varnum,
    };
};

pub const PlaySetHeadRotationPacket = struct {
    entity_id: i32,
    head_yaw: u8,

    pub const ENCODING: craft_io.Encoding(@This()) = .{
        .entity_id = .varnum,
    };
};

pub const PlayUpdateEntityPositionAndRotationPacket = struct {
    entity_id: i32,
    delta_pos: Vector3(i16),
    yaw: u8,
    pitch: u8,
    on_ground: bool,

    pub const ENCODING: craft_io.Encoding(@This()) = .{
        .entity_id = .varnum,
    };
};

pub const PlayUpdateAttributesPacket = struct {
    pub const ModifierData = struct {
        id: []const u8,
        amount: f64,
        operation: enum(u8) {
            add_exact = 0,
            add_percent = 1,
            scale_percent = 2,
        },

        pub const ENCODING: craft_io.Encoding(@This()) = .{
            .id = .{ .max_items = MAX_IDENTIFIER_SIZE },
        };
    };

    entity_id: i32,
    properties: []const struct {
        id: i32,
        value: f64,
        modifiers: []const ModifierData,

        pub const ENCODING: craft_io.Encoding(@This()) = .{
            .id = .varnum,
        };
    },

    pub const ENCODING: craft_io.Encoding(@This()) = .{
        .entity_id = .varnum,
    };
};

pub const PlaySetEquipmentPacket = struct {
    pub const EquipmentSlot = enum(u8) {
        main_hand = 0,
        off_hand = 1,
        boots = 2,
        leggings = 3,
        chestplate = 4,
        helmet = 5,
        body = 6,
    };

    pub const Equipment = struct {
        slot: EquipmentSlot,
        item: Slot,
    };

    // some helper types for encoding / decoding
    // a u7 version of the same u8 byte enum
    const EquipmentSlotU7: type = @Type(.{ .@"enum" = .{
        .fields = @typeInfo(EquipmentSlot).@"enum".fields,
        .tag_type = u7,
        .decls = &.{},
        .is_exhaustive = true,
    } });

    // flag and slot as a u8, where MSB is "has_more" and
    // rest (7 bits) is the slot enum
    const FlagAndSlot = packed struct {
        slot: EquipmentSlotU7,
        has_more: bool,
    };

    // the actual items encoded in the array
    const ArrayItem = struct {
        flag_and_slot: FlagAndSlot,
        item: Slot,
    };

    entity_id: i32,
    equipment: []const Equipment,

    pub const ENCODING: craft_io.Encoding(@This()) = .{
        .entity_id = .varnum,
    };

    pub fn craftEncode(
        packet: PlaySetEquipmentPacket,
        writer: anytype,
        allocator: std.mem.Allocator,
        diag: Diag,
        comptime encoding: craft_io.Encoding(PlaySetEquipmentPacket),
    ) !usize {
        var bytes_written: usize = 0;

        bytes_written += try craft_io.encode(
            packet.entity_id,
            writer,
            allocator,
            try diag.child(.{ .field = "entity_id" }),
            encoding.entity_id,
        );

        if (packet.equipment.len > 0) {
            const equipment_diag = try diag.child(.{ .field = "equipment" });
            const last_idx = packet.equipment.len - 1;
            for (packet.equipment, 0..) |equipment, idx| {
                const item_diag = try equipment_diag.child(.{ .index = idx });
                const item: ArrayItem = .{
                    .flag_and_slot = .{
                        .has_more = idx < last_idx,
                        .slot = @enumFromInt(@intFromEnum(equipment.slot)),
                    },
                    .item = equipment.item,
                };
                bytes_written += try craft_io.encode(
                    item,
                    writer,
                    allocator,
                    item_diag,
                    comptime craft_io.defaultEncoding(ArrayItem),
                );
            }
        }

        return bytes_written;
    }

    pub fn craftDecode(
        reader: anytype,
        arena_allocator: *std.heap.ArenaAllocator,
        diag: Diag,
        comptime encoding: craft_io.Encoding(PlaySetEquipmentPacket),
    ) craft_io.DecodeRet(PlaySetEquipmentPacket, @TypeOf(reader)) {
        var bytes_read: usize = 0;
        var out: PlaySetEquipmentPacket = undefined;
        out.entity_id = (try craft_io.decode(
            i32,
            reader,
            arena_allocator,
            try diag.child(.{ .field = "entity_id" }),
            encoding.entity_id,
        )).unwrap(&bytes_read);

        // literally wtf
        const allocator = arena_allocator.allocator();
        var al: std.ArrayList(Equipment) = .init(allocator);
        defer al.deinit();

        const equipment_diag = try diag.child(.{ .field = "equipment" });
        var idx: usize = 0;
        while (true) {
            const item_diag = try equipment_diag.child(.{ .index = idx });
            const next_item: ArrayItem = (try craft_io.decode(
                ArrayItem,
                reader,
                arena_allocator,
                item_diag,
                comptime craft_io.defaultEncoding(ArrayItem),
            )).unwrap(&bytes_read);

            try al.append(.{
                .slot = @enumFromInt(@intFromEnum(next_item.flag_and_slot.slot)),
                .item = next_item.item,
            });
            idx += 1;
            if (!next_item.flag_and_slot.has_more) {
                break;
            }
        }
        out.equipment = try al.toOwnedSlice();
        return .{
            .value = out,
            .bytes_read = bytes_read,
        };
    }
};

pub const PlayTeleportEntityPacket = struct {
    entity_id: i32,
    position: Vector3(f64),
    velocity: Vector3(f64),
    yaw: f32,
    pitch: f32,
    on_ground: bool,

    pub const ENCODING: craft_io.Encoding(@This()) = .{
        .entity_id = .varnum,
    };
};

pub const PlaySpawnEntityPacket = struct {
    entity_id: i32,
    entity_uuid: UUID,
    type: i32,
    position: Vector3(f64),
    pitch: u8,
    yaw: u8,
    head_yaw: u8,
    data: i32,
    velocity: Vector3(i16),

    pub const ENCODING: craft_io.Encoding(@This()) = .{
        .entity_id = .varnum,
        .type = .varnum,
        .data = .varnum,
    };
};

pub const ParticleID = enum(i32) {
    angry_villager = 0,
    block = 1,
    block_marker = 2,
    bubble = 3,
    cloud = 4,
    crit = 5,
    damage_indicator = 6,
    dragon_breath = 7,
    dripping_lava = 8,
    falling_lava = 9,
    landing_lava = 10,
    dripping_water = 11,
    falling_water = 12,
    dust = 13,
    dust_color_transition = 14,
    effect = 15,
    elder_guardian = 16,
    enchanted_hit = 17,
    enchant = 18,
    end_rod = 19,
    entity_effect = 20,
    explosion_emitter = 21,
    explosion = 22,
    gust = 23,
    small_gust = 24,
    gust_emitter_large = 25,
    gust_emitter_small = 26,
    sonic_bool = 27,
    falling_dust = 28,
    firework = 29,
    fishing = 30,
    flame = 31,
    infested = 32,
    cherry_leaves = 33,
    pale_oak_leaves = 34,
    tinted_leaves = 35,
    sculk_soul = 36,
    sculk_charge = 37,
    sculk_charge_pop = 38,
    soul_fire_flame = 39,
    soul = 40,
    flash = 41,
    happy_villager = 42,
    composter = 43,
    heart = 44,
    instant_effect = 45,
    item = 46,
    vibration = 47,
    trail = 48,
    item_slime = 49,
    item_cobweb = 50,
    item_snowball = 51,
    large_smoke = 52,
    lava = 53,
    mycelium = 54,
    note = 55,
    poof = 56,
    portal = 57,
    rain = 58,
    smoke = 59,
    white_smoke = 60,
    sneeze = 61,
    spit = 62,
    squid_ink = 63,
    sweep_attack = 64,
    totem_of_undying = 65,
    underwater = 66,
    splash = 67,
    witch = 68,
    bubble_pop = 69,
    current_down = 70,
    bubble_column_up = 71,
    nautilus = 72,
    dolphin = 73,
    campfire_cosy_smoke = 74,
    campfire_signal_smoke = 75,
    dripping_honey = 76,
    falling_honey = 77,
    landing_honey = 78,
    falling_nectar = 79,
    falling_spore_blossom = 80,
    ash = 81,
    crimson_spore = 83,
    spore_blossom_air = 84,
    dripping_obsidian_tear = 85,
    falling_obsidian_tear = 86,
    landing_obsidian_tear = 87,
    reverse_portal = 88,
    white_ash = 89,
    small_flame = 90,
    snowflake = 91,
    dripping_dripstone_lava = 92,
    falling_dripstone_lava = 93,
    dripping_dripstone_water = 94,
    falling_dripstone_water = 95,
    glow_squid_ink = 96,
    glow = 97,
    wax_on = 98,
    wax_off = 99,
    electric_spark = 100,
    scrape = 101,
    shriek = 102,
    egg_crack = 103,
    dust_plume = 104,
    trial_spawner_detection = 105,
    trial_spawner_detection_ominous = 106,
    vault_connection = 107,
    dust_pillar = 108,
    ominous_spawning = 109,
    raid_omen = 110,
    trial_omen = 111,
    block_crumble = 112,
    firefly = 113,

    pub const ENCODING: craft_io.Encoding(@This()) = .varnum;
};

pub const Color = struct {
    alpha: u8,
    red: u8,
    green: u8,
    blue: u8,
};

pub const PositionSourceType = enum(i32) {
    block = 0,
    entity = 1,

    pub const ENCODING: craft_io.Encoding(@This()) = .varnum;
};

pub const PositionSource = union(PositionSourceType) { block: struct {
    block_position: craft_io.Position,
}, entity: struct {
    entity_id: i32,
    entity_eye_height: f32,

    pub const ENCODING: craft_io.Encoding(@This()) = .{
        .entity_id = .varnum,
    };
} };

pub const Particle = union(ParticleID) {
    pub const BlockParticleData = struct {
        block_state: i32,

        pub const ENCODING: craft_io.Encoding(@This()) = .{
            .block_state = .varnum,
        };
    };

    angry_villager,
    block: BlockParticleData,
    block_marker: BlockParticleData,
    bubble,
    cloud,
    crit,
    damage_indicator,
    dragon_breath,
    dripping_lava,
    falling_lava,
    landing_lava,
    dripping_water,
    falling_water,
    dust: struct {
        color: Color,
        scale: f32,
    },
    dust_color_transition: struct {
        from_color: Color,
        to_color: Color,
        scale: f32,
    },
    effect,
    elder_guardian,
    enchanted_hit,
    enchant,
    end_rod,
    entity_effect: struct {
        color: Color,
    },
    explosion_emitter,
    explosion,
    gust,
    small_gust,
    gust_emitter_large,
    gust_emitter_small,
    sonic_bool,
    falling_dust: BlockParticleData,
    firework,
    fishing,
    flame,
    infested,
    cherry_leaves,
    pale_oak_leaves,
    tinted_leaves: struct {
        color: Color,
    },
    sculk_soul,
    sculk_charge: struct {
        roll: f32,
    },
    sculk_charge_pop,
    soul_fire_flame,
    soul,
    flash,
    happy_villager,
    composter,
    heart,
    instant_effect,
    item: struct {
        item: Slot,
    },
    vibration: struct {
        position: PositionSource,
        ticks: i32,

        pub const ENCODING: craft_io.Encoding(@This()) = .{
            .ticks = .varnum,
        };
    },
    trail: struct {
        target: Vector3(f64),
        color: Color,
        duration: i32,

        pub const ENCODING: craft_io.Encoding(@This()) = .{
            .duration = .varnum,
        };
    },
    item_slime,
    item_cobweb,
    item_snowball,
    large_smoke,
    lava,
    mycelium,
    note,
    poof,
    portal,
    rain,
    smoke,
    white_smoke,
    sneeze,
    spit,
    squid_ink,
    sweep_attack,
    totem_of_undying,
    underwater,
    splash,
    witch,
    bubble_pop,
    current_down,
    bubble_column_up,
    nautilus,
    dolphin,
    campfire_cosy_smoke,
    campfire_signal_smoke,
    dripping_honey,
    falling_honey,
    landing_honey,
    falling_nectar,
    falling_spore_blossom,
    ash,
    crimson_spore,
    spore_blossom_air,
    dripping_obsidian_tear,
    falling_obsidian_tear,
    landing_obsidian_tear,
    reverse_portal,
    white_ash,
    small_flame,
    snowflake,
    dripping_dripstone_lava,
    falling_dripstone_lava,
    dripping_dripstone_water,
    falling_dripstone_water,
    glow_squid_ink,
    glow,
    wax_on,
    wax_off,
    electric_spark,
    scrape,
    shriek: struct {
        delay: i32,

        pub const ENCODING: craft_io.Encoding(@This()) = .{
            .delay = .varnum,
        };
    },
    egg_crack,
    dust_plume,
    trial_spawner_detection,
    trial_spawner_detection_ominous,
    vault_connection,
    dust_pillar: BlockParticleData,
    ominous_spawning,
    raid_omen,
    trial_omen,
    block_crumble: BlockParticleData,
    firefly,
};

pub const EntityMetadata = struct {
    pub const Entry = struct {
        index: u8,
        value: Value,
    };

    pub const ValueType = enum(i32) {
        byte = 0,
        varint = 1,
        varlong = 2,
        float = 3,
        string = 4,
        text_component = 5,
        optional_text_component = 6,
        slot = 7,
        boolean = 8,
        rotations = 9,
        position = 10,
        optional_position = 11,
        direction = 12,
        optional_living_entity_reference = 13,
        block_state = 14,
        optional_block_state = 15,
        nbt = 16,
        particle = 17,
        particles = 18,
        villager_data = 19,
        optional_varint = 20,
        pose = 21,
        cat_variant = 22,
        cow_variant = 23,
        wolf_variant = 24,
        wolf_sound_variant = 25,
        frog_variant = 26,
        pig_variant = 27,
        chicken_variant = 28,
        optional_global_position = 29,
        painting_variant = 30,
        sniffer_state = 31,
        armadillo_state = 32,
        vector3 = 33,
        quaternion = 34,

        pub const ENCODING: craft_io.Encoding(@This()) = .varnum;
    };

    pub const Value = union(ValueType) {
        byte: u8,
        varint: i32,
        varlong: i64,
        float: f32,
        string: []const u8,
        text_component: TextComponent,
        optional_text_component: ?TextComponent,
        slot: Slot,
        boolean: bool,
        rotations: Vector3(f32),
        position: craft_io.Position,
        optional_position: ?craft_io.Position,
        direction: enum(i32) {
            down = 0,
            up = 1,
            north = 2,
            south = 3,
            west = 4,
            east = 5,

            pub const ENCODING: craft_io.Encoding(@This()) = .varnum;
        },
        optional_living_entity_reference: ?UUID,
        block_state: i32,
        optional_block_state: i32, // 0 = air, otherwise id in block state registry
        nbt: nbt.NamedTag,
        particle: Particle,
        particles: []const Particle,
        villager_data: struct {
            type: i32,
            profession: i32,
            level: i32,

            pub const ENCODING: craft_io.Encoding(@This()) = .{
                .type = .varnum,
                .profession = .varnum,
                .level = .varnum,
            };
        },
        optional_varint: i32, // 0 == absent, otherwise value + 1
        pose: enum(i32) {
            standing = 0,
            fall_flying = 1,
            sleeping = 2,
            swimming = 3,
            spin_attack = 4,
            sneaking = 5,
            long_jumping = 6,
            dying = 7,
            croaking = 8,
            using_tongue = 9,
            sitting = 10,
            roaring = 11,
            sniffing = 12,
            emerging = 13,
            digging = 14,
            sliding = 15,
            shooting = 16,
            inhaling = 17,

            pub const ENCODING: craft_io.Encoding(@This()) = .varnum;
        },
        cat_variant: i32,
        cow_variant: i32,
        wolf_variant: i32,
        wolf_sound_variant: i32,
        frog_variant: i32,
        pig_variant: i32,
        chicken_variant: i32,
        optional_global_position: ?struct {
            id: []const u8,
            position: craft_io.Position,

            pub const ENCODING: craft_io.Encoding(@This()) = .{
                .id = .{ .max_items = MAX_IDENTIFIER_SIZE },
            };
        },
        painting_variant: craft_io.IdOr(PaintingVariant),
        sniffer_state: enum(i32) {
            idling = 0,
            feeling_happy = 1,
            scenting = 2,
            sniffing = 3,
            searching = 4,
            digging = 5,
            rising = 6,

            pub const ENCODING: craft_io.Encoding(@This()) = .varnum;
        },
        armadillo_state: enum(i32) {
            idle = 0,
            rolling = 1,
            scared = 2,
            unrolling = 3,

            pub const ENCODING: craft_io.Encoding(@This()) = .varnum;
        },
        vector3: Vector3(f32),
        quaternion: struct {
            x: f32,
            y: f32,
            z: f32,
            w: f32,
        },

        pub const ENCODING: craft_io.Encoding(@This()) = .{
            .fields = .{
                .varint = .varnum,
                .varlong = .varnum,
                .string = .{ .max_items = MAX_IDENTIFIER_SIZE },
                .block_state = .varnum,
                .optional_block_state = .varnum,
                .optional_varint = .varnum,
                .cat_variant = .varnum,
                .cow_variant = .varnum,
                .wolf_variant = .varnum,
                .wolf_sound_variant = .varnum,
                .frog_variant = .varnum,
                .pig_variant = .varnum,
                .chicken_variant = .varnum,
            },
        };
    };

    entries: []const Entry,

    pub const CraftEncoding: type = struct {
        value: craft_io.Encoding(Value),
    };

    pub const ENCODING: CraftEncoding = .{
        .value = craft_io.defaultEncoding(Value),
    };

    const SENTINEL_INDEX_VALUE: u8 = 0xff;

    pub fn craftEncode(
        md: EntityMetadata,
        writer: anytype,
        allocator: std.mem.Allocator,
        diag: Diag,
        comptime encoding: CraftEncoding,
    ) !usize {
        var bytes_written: usize = 0;

        const entries_diag = try diag.child(.{ .field = "entries" });
        for (md.entries, 0..) |entry, idx| {
            const idx_diag = try entries_diag.child(.{ .index = idx });
            bytes_written += try craft_io.encode(
                entry,
                writer,
                allocator,
                idx_diag,
                .{ .value = encoding.value },
            );
        }
        const last_idx_diag = try entries_diag.child(.{ .index = md.entries.len });
        const last_idx_index_diag = try last_idx_diag.child(.{ .field = "index" });
        bytes_written += try craft_io.encode(
            SENTINEL_INDEX_VALUE,
            writer,
            allocator,
            last_idx_index_diag,
            {},
        );
        return bytes_written;
    }

    pub fn craftDecode(
        reader: anytype,
        arena_allocator: *std.heap.ArenaAllocator,
        diag: Diag,
        comptime encoding: CraftEncoding,
    ) craft_io.DecodeRet(@This(), @TypeOf(reader)) {
        var bytes_read: usize = 0;

        const allocator = arena_allocator.allocator();
        var al: std.ArrayList(Entry) = .init(allocator);
        defer al.deinit();

        var idx: usize = 0;
        const entries_diag = try diag.child(.{ .field = "entries" });
        while (true) {
            const idx_diag = try entries_diag.child(.{ .index = idx });
            const index_diag = try idx_diag.child(.{ .field = "index" });

            const index: u8 = (try craft_io.decode(
                u8,
                reader,
                arena_allocator,
                index_diag,
                {},
            )).unwrap(&bytes_read);
            if (index == SENTINEL_INDEX_VALUE) {
                break;
            }

            const value_diag = try idx_diag.child(.{ .field = "value" });
            const value = (try craft_io.decode(
                Value,
                reader,
                arena_allocator,
                value_diag,
                encoding.value,
            )).unwrap(&bytes_read);

            try al.append(.{ .index = index, .value = value });
            idx += 1;
        }

        return .{
            .value = .{ .entries = try al.toOwnedSlice() },
            .bytes_read = bytes_read,
        };
    }
};

pub const PlaySetEntityMetadataPacket = struct {
    entity_id: i32,
    metadata: EntityMetadata,

    pub const ENCODING: craft_io.Encoding(@This()) = .{
        .entity_id = .varnum,
    };
};

pub const PlaySetEntityVelocityPacket = struct {
    entity_id: i32,
    velocity: Vector3(i16),

    pub const ENCODING: craft_io.Encoding(@This()) = .{
        .entity_id = .varnum,
    };
};

pub const PlayBlockUpdatePacket = struct {
    location: craft_io.Position,
    block_id: i32,

    pub const ENCODING: craft_io.Encoding(@This()) = .{
        .block_id = .varnum,
    };
};

pub const PlayUpdateSectionBlocksPacket = struct {
    pub const ChunkPosition = packed struct {
        y: i20,
        z: i22,
        x: i22,
    };

    pub const BlockUpdate = packed struct {
        rel_y: i4,
        rel_z: i4,
        rel_x: i4,
        block_state_id: i32,

        pub const ENCODING: craft_io.Encoding(@This()) = .{
            .as_int = .{ .encoding = .varnum, .bits = 64 },
        };
    };

    chunk_section_position: ChunkPosition,
    blocks: []const BlockUpdate,
};

pub const PlayUpdateEntityRotationPacket = struct {
    entity_id: i32,
    yaw: i8,
    pitch: i8,
    on_ground: bool,

    pub const ENCODING: craft_io.Encoding(@This()) = .{
        .entity_id = .varnum,
    };
};

pub const PlayDisconnectPacket = struct {
    reason: TextComponent,
};

pub const PlayPlayerChatMessagePacket = struct {
    pub const Header = struct {
        global_index: i32,
        sender: UUID,
        index: i32,
        message_signature: ?[256]u8,

        pub const ENCODING: craft_io.Encoding(@This()) = .{
            .global_index = .varnum,
            .index = .varnum,
        };
    };

    pub const Body = struct {
        message: []const u8,
        timestamp: i64,
        salt: i64,

        pub const ENCODING: craft_io.Encoding(@This()) = .{
            .message = .{ .max_items = 256 },
        };
    };

    pub const SignatureItem = struct {
        message_id: i32,
        signature: ?[256]u8,

        pub const ENCODING: craft_io.Encoding(@This()) = .{
            .message_id = .varnum,
        };
    };

    pub const FilterType = enum(i32) {
        pass_through = 0,
        fully_filtered = 1,
        partially_filtered = 2,

        pub const ENCODING: craft_io.Encoding(@This()) = .varnum;
    };

    pub const Filter = union(FilterType) {
        pass_through,
        fully_filtered,
        partially_filtered: []i64,
    };

    pub const Formatting = struct {
        chat_type: craft_io.IdOr(nbt.NamedTag),
        sender_name: TextComponent,
        target_name: ?TextComponent,
    };

    header: Header,
    body: Body,
    signatures: []const SignatureItem,
    unsigned_content: ?TextComponent,
    filter: Filter,
    formatting: Formatting,
};

pub const PlayRemoveEntitiesPacket = struct {
    entity_ids: []const i32,

    pub const ENCODING: craft_io.Encoding(@This()) = .{
        .entity_ids = .{ .items = .varnum },
    };
};

pub const PlayWorldEventPacket = struct {
    event: i32,
    location: craft_io.Position,
    data: i32,
    disable_relative_volume: bool,
};

pub const PlayDamageEventPacket = struct {
    entity_id: i32,
    damage_type_id: i32,
    source_cause_id: craft_io.IdOr(void),
    source_direct_id: craft_io.IdOr(void),
    source_position: ?Vector3(f64),

    pub const ENCODING: craft_io.Encoding(@This()) = .{
        .entity_id = .varnum,
        .damage_type_id = .varnum,
    };
};

pub const PlayServerboundPacketID = enum(i32) {
    confirm_teleportation = 0x00,
    chat = 0x07,
    client_status = 0x0A,
    keep_alive = 0x1A,

    pub fn idFor(comptime Packet: type) ?@This() {
        return switch (Packet) {
            PlayConfirmTeleportationPacket => .confirm_teleportation,
            PlayClientStatusPacket => .client_status,
            PlayChatMessagePacket => .chat,
            KeepAlivePacket => .keep_alive,
            else => null,
        };
    }

    pub fn writePacket(conn: anytype, packet: anytype, diag: Diag) !usize {
        if (idFor(@TypeOf(packet))) |pkt_id| {
            return conn.writePacket(@intFromEnum(pkt_id), packet, diag);
        } else {
            return error.UnknownPacket;
        }
    }
};

pub const PlayConfirmTeleportationPacket = struct {
    teleport_id: i32,

    pub const ENCODING: craft_io.Encoding(@This()) = .{
        .teleport_id = .varnum,
    };
};

pub const PlayClientStatusPacket = struct {
    action: enum(i32) {
        perform_respawn = 0x00,
        request_stats = 0x01,

        pub const ENCODING: craft_io.Encoding(@This()) = .varnum;
    },
};

pub const PlayChatMessagePacket = struct {
    message: []const u8,
    timestamp: i64,
    salt: i64,
    signature: ?[]const u8,
    message_count: i32,
    acknowledged: [3]u8,
    checksum: u8,

    pub fn simple(msg: []const u8) @This() {
        return .{
            .message = msg,
            .timestamp = std.time.milliTimestamp(),
            .salt = std.Random.int(std.crypto.random, i64),
            .signature = null,
            .message_count = 0,
            .acknowledged = .{ 0, 0, 0 },
            .checksum = 0,
        };
    }

    pub const ENCODING: craft_io.Encoding(@This()) = .{
        .message = .{ .max_items = 256 },
        .message_count = .varnum,
    };
};
