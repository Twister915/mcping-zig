const std = @import("std");
const CraftConn = @import("CraftConn.zig");
const packets = @import("packets.zig");
const UUID = @import("UUID.zig");
const craft_chat = @import("chat.zig");
const draw = @import("draw.zig");
const craft_io = @import("io.zig");

const log = std.log.scoped(.main);

// setup testing to run all tests in all referenced files
test {
    std.testing.refAllDeclsRecursive(@This());
}

pub const std_options: std.Options = .{
    .log_level = if (std.debug.runtime_safety) .debug else .info,
};

pub const gpa_config: std.heap.GeneralPurposeAllocatorConfig = .{
    .verbose_log = std.debug.runtime_safety,
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(gpa_config).init;
    if (std.debug.runtime_safety) {
        defer _ = gpa.detectLeaks();
    }

    const allocator = gpa.allocator();

    var any: bool = false;
    var args = std.process.args();
    _ = args.skip();
    while (args.next()) |arg| {
        handleTarget(allocator, arg);
        any = true;
    }

    if (!any) {
        // this is a hack for debugging from within vscode
        if (std.debug.runtime_safety) {
            handleTarget(allocator, "rpi4.jhome");
        } else {
            log.err("must specify at least one target host", .{});
        }
    }
}

fn handleTarget(allocator: std.mem.Allocator, arg: []const u8) void {
    const target = targetFromArg(arg) catch |err| {
        log.err("error parsing argument {s} -> {any}", .{ arg, err });
        return;
    };

    var diag_arena_alloc = std.heap.ArenaAllocator.init(allocator);
    defer diag_arena_alloc.deinit();

    var diag_state = craft_io.Diag.State.init(&diag_arena_alloc);

    pingPrint(allocator, target, diag_state.diag()) catch |err| {
        dumpDiagReports(&diag_state);
        log.err("failed to ping {s} -> {any}", .{ arg, err });
    };

    loginOffline(allocator, target, .{
        .username = "Notch",
        .uuid = .random(std.crypto.random),
    }, diag_state.diag()) catch |err| {
        dumpDiagReports(&diag_state);
        log.err("failed log into server {s} -> {any}", .{ arg, err });
    };
}

fn targetFromArg(raw: []const u8) !Target {
    var target: Target = .{ .host = raw };
    if (std.mem.indexOfScalar(u8, raw, ':')) |raw_port_idx| {
        const port_start_idx = raw_port_idx + 1;
        if (raw.len > port_start_idx) {
            const raw_port = raw[raw_port_idx..];
            if (std.fmt.parseInt(u16, raw_port, 10) catch null) |parsed| {
                const host = raw[0..raw_port_idx];
                target.host = host;
                target.port = parsed;
            }
        }
    }
    return target;
}

fn pingPrint(parent_allocator: std.mem.Allocator, target: Target, diag: craft_io.Diag) !void {
    var arena_allocator = std.heap.ArenaAllocator.init(parent_allocator);
    defer arena_allocator.deinit();

    const allocator = arena_allocator.allocator();

    const response = try ping(target, &arena_allocator, diag);

    var bash_str_buf = std.ArrayList(u8).init(allocator);
    try craft_chat.writeBash(
        response.status.description,
        .{ .translate_traditional = true },
        .{},
        bash_str_buf.writer(),
    );
    try bash_str_buf.appendSlice("\n");

    try std.io.getStdOut().writeAll(bash_str_buf.items);

    if (response.status.favicon) |favicon_raw| {
        const favicon_decoded = try favicon_raw.decode(allocator);
        const favicon_printer = try draw.FaviconPrinter.init(
            favicon_decoded,
            .{},
            arena_allocator.allocator(),
        );

        var favicon_printed_buf = std.ArrayList(u8).init(allocator);
        try favicon_printer.draw(favicon_printed_buf.writer());
        try favicon_printed_buf.appendSlice("\n");
        try std.io.getStdOut().writeAll(favicon_printed_buf.items);
    }
}

const Target = struct {
    protocol_version: i32 = 769,
    host: []const u8,
    port: u16 = 25565,
};

const PingResponse = struct {
    status: packets.Status,
    latency_ms: ?i64 = null,
};

fn ping(target: Target, arena_allocator: *std.heap.ArenaAllocator, diag: craft_io.Diag) !PingResponse {
    var conn = try CraftConn.connect(arena_allocator.allocator(), target.host, target.port);
    defer conn.deinit(); // <-- close connection at the end of this function

    // state = handshaking
    // [tx]: Handshaking Packet :: 0x00
    _ = try conn.writePacket(0x00, packets.HandshakingPacket{
        .version = target.protocol_version,
        .address = target.host,
        .port = target.port,
        .next_state = .status,
    }, diag);

    // state = status
    // [tx]: Status Request Packet :: 0x00
    _ = try conn.writePacket(0x00, {}, diag);
    // [rx]: Status Response Packet :: 0x00
    const status_response_packet = try conn.readAndExpectPacket(
        0x00,
        packets.StatusResponsePacket,
        arena_allocator,
    );
    // [tx]: Status Ping Packet :: 0x01
    const ping_at_ms = std.time.milliTimestamp();
    _ = try conn.writePacket(0x01, packets.StatusPingPongPacket{ .timestamp = ping_at_ms }, diag);

    // [rx]: Status Pong Packet : 0x01
    const pong_packet = try conn.readAndExpectPacket(0x01, packets.StatusPingPongPacket, arena_allocator);
    const latency_ms: ?i64 = if (pong_packet.timestamp == ping_at_ms) std.time.milliTimestamp() - pong_packet.timestamp else null;
    return .{
        .status = status_response_packet.status,
        .latency_ms = latency_ms,
    };
}

const Profile = struct {
    username: []const u8,
    uuid: UUID,
};

fn loginOffline(allocator: std.mem.Allocator, target: Target, profile: Profile, diag: craft_io.Diag) !void {
    var conn = try CraftConn.connect(allocator, target.host, target.port);
    defer conn.deinit();

    log.debug("switched to handshaking state", .{});

    // use "allocator" for the connection itself, but use arena_allocator for deserializing packets
    // so that we can reset the arena_allocator after we finish processing each packet
    var arena_allocator = std.heap.ArenaAllocator.init(allocator);
    defer arena_allocator.deinit();

    // state = handshaking
    _ = try conn.writePacket(0x00, packets.HandshakingPacket{
        .address = target.host,
        .port = target.port,
        .version = target.protocol_version,
        .next_state = .login,
    }, diag);

    // state = login
    log.debug("switched to login state", .{});

    // 0x00 LoginStart client ----> server
    _ = try conn.writePacket(0x00, packets.LoginStartPacket{
        .name = profile.username,
        .uuid = profile.uuid,
    }, diag);

    login_state: while (true) {
        const login_packet = try conn.readPacket();
        switch (login_packet.id) {
            0x00 => {
                const disconnect_packet = try login_packet.decodeAs(packets.DisconnectPacket, &arena_allocator);
                defer _ = arena_allocator.reset(.retain_capacity);

                std.debug.print("disconnected from {s} ---> {s}\n", .{ target.host, disconnect_packet.reason });
                return error.Disconnected;
            },
            0x01 => {
                // encryption request
                const encryption_request_packet = try login_packet.decodeAs(packets.EncryptionRequestPacket, &arena_allocator);
                defer _ = arena_allocator.reset(.retain_capacity);

                log.warn("encryption requested ({}) but not supported", .{encryption_request_packet});
                return error.EncryptionRequested;
            },
            0x02 => {
                // login success
                // we skip decode because we don't use the data
                // const login_success_packet = try login_packet.decodeAs(packets.LoginSuccessPacket, &arena_allocator);
                // defer arena_allocator.reset(.retain_capacity);

                // send login acknowledged
                _ = try conn.writePacket(0x03, {}, diag);
                break :login_state;
            },
            0x03 => {
                // set compression
                const set_compression_packet = try login_packet.decodeAs(packets.SetCompressionPacket, &arena_allocator);
                defer _ = arena_allocator.reset(.retain_capacity);

                try conn.setCompressionThreshold(@intCast(set_compression_packet.threshold));
            },
            0x04 => {
                // login plugin message
                //
                // from the wiki:
                //  "these messages follow a lock-step request/response scheme,
                //   where the client is expected to respond to a request indicating
                //   whether it understood. The vanilla client always responds that
                //   it hasn't understood, and sends an empty payload."
                //
                // so that's what I'm going to do... send empty LoginPluginResponsePacket

                const ping_request_packet = try login_packet.decodeAs(packets.LoginPluginRequestPacket, &arena_allocator);
                defer _ = arena_allocator.reset(.retain_capacity);

                // login plugin response = 0x02
                _ = try conn.writePacket(0x02, packets.LoginPluginResponsePacket{
                    .message_id = ping_request_packet.message_id,
                    .data = null,
                }, diag);
            },
            0x05 => {
                // cookie request
                // we don't have cookie storage yet, so let's just send back an empty cookie packet

                const cookie_request_packet = try login_packet.decodeAs(packets.CookieRequestPacket, &arena_allocator);
                defer _ = arena_allocator.reset(.retain_capacity);

                _ = try conn.writePacket(0x04, packets.CookieResponsePacket{
                    .key = cookie_request_packet.key, // borrow so we don't deinit twice
                    .payload = null,
                }, diag);
            },
            else => {
                diag.report(
                    error.BadPacketId,
                    "packet",
                    "bad packet id in login state: 0x{X:02}",
                    .{@as(u32, @intCast(login_packet.id))},
                );
                return error.BadPacketId;
            },
        }
    }

    log.debug("switched to configuration state", .{});

    // enter configuration state
    _ = try conn.writePacket(0x00, packets.ConfigClientInformationPacket{
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
    }, diag);

    configuration_state: while (true) {
        const configuration_packet = try conn.readPacket();
        switch (configuration_packet.id) {
            0x00 => {
                // cookie request
                const cookie_request_packet = try configuration_packet.decodeAs(packets.CookieRequestPacket, &arena_allocator);
                defer _ = arena_allocator.reset(.retain_capacity);

                _ = try conn.writePacket(0x01, packets.CookieResponsePacket{
                    .key = cookie_request_packet.key,
                    .payload = null,
                }, diag);
            },
            0x01 => {}, // plugin message, skip
            0x02 => {
                // disconnect
                const disconnect_packet = try configuration_packet.decodeAs(packets.DisconnectPacket, &arena_allocator);
                defer _ = arena_allocator.reset(.retain_capacity);

                log.err("disconnected from {s} --> {s}", .{ target.host, disconnect_packet.reason });
                return error.Disconnected;
            },
            0x03 => {
                // finish configuration
                _ = try conn.writePacket(0x03, {}, diag);
                break :configuration_state;
            },
            0x04 => {
                // client bound keep-alive
                const keep_alive_packet = try configuration_packet.decodeAs(packets.KeepAlivePacket, &arena_allocator);
                defer _ = arena_allocator.reset(.retain_capacity);

                _ = try conn.writePacket(0x04, keep_alive_packet, diag);
            },
            0x05 => {
                // ping packet
                const ping_packet = try configuration_packet.decodeAs(packets.ConfigPingPacket, &arena_allocator);
                defer _ = arena_allocator.reset(.retain_capacity);

                _ = try conn.writePacket(0x05, ping_packet, diag);
            },
            0x06 => {}, // reset chat, do nothing
            0x07 => {
                const registry_data_packet = try configuration_packet.decodeAs(packets.ConfigRegistryDataPacket, &arena_allocator);
                defer _ = arena_allocator.reset(.retain_capacity);

                for (registry_data_packet.entries) |registry_entry| {
                    log.debug("registry({s}): {s} -> {any}", .{ registry_data_packet.registry_id, registry_entry.id, registry_entry.data });
                }
            },
            0x08 => {}, // remove resource pack, do nothing
            0x09 => {
                // add resource pack
                const add_resource_pack_packet = try configuration_packet.decodeAs(packets.ConfigAddResourcePackPacket, &arena_allocator);
                defer _ = arena_allocator.reset(.retain_capacity);

                log.debug("add_resource_pack: id={}, url={s}, hash={s}, forced={any}, prompt_msg={?}", .{
                    add_resource_pack_packet.id,
                    add_resource_pack_packet.url,
                    add_resource_pack_packet.hash,
                    add_resource_pack_packet.forced,
                    add_resource_pack_packet.prompt_message,
                });

                _ = try conn.writePacket(0x06, packets.ConfigResourcePackResponsePacket{
                    .id = add_resource_pack_packet.id,
                    .result = .declined,
                }, diag);
            },
            0x0A => {}, // store cookie, do nothing
            0x0B => {}, // transfer, not implemented
            0x0C => {
                // feature flags
                const feature_flags_packet = try configuration_packet.decodeAs(packets.ConfigFeatureFlagsPacket, &arena_allocator);
                defer _ = arena_allocator.reset(.retain_capacity);

                for (feature_flags_packet.feature_flags) |feature_flag| {
                    log.debug("feature flag = {s}", .{feature_flag});
                }
            },
            0x0D => {
                // update tags
                const update_tags_packet = try configuration_packet.decodeAs(packets.ConfigUpdateTagsPacket, &arena_allocator);
                defer _ = arena_allocator.reset(.retain_capacity);

                for (update_tags_packet.registry_tags) |tags| {
                    for (tags.tags) |tag| {
                        log.debug("tags({s}) {s} -> {any}", .{ tags.registry_id, tag.name, tag.entries });
                    }
                }
            },
            0x0E => {
                // clientbound known packs
                const known_packs_packet = try configuration_packet.decodeAs(packets.ConfigKnownPacksPacket, &arena_allocator);
                defer _ = arena_allocator.reset(.retain_capacity);

                var sb_known_packs = std.ArrayList(packets.ConfigKnownPacksPacket.KnownPack).init(arena_allocator.allocator());
                for (known_packs_packet.known_packs) |known_pack| {
                    if (std.mem.eql(u8, known_pack.namespace, "minecraft") and std.mem.eql(u8, known_pack.id, "core")) {
                        try sb_known_packs.append(known_pack);
                    }

                    log.debug("server declared known pack {any}", .{known_pack});
                }

                if (sb_known_packs.items.len == 0) {
                    log.warn("about to tell the server we know about 0 packs, probably won't work", .{});
                }

                _ = try conn.writePacket(0x07, packets.ConfigKnownPacksPacket{ .known_packs = sb_known_packs.items }, diag);
            },
            0x0F => {}, // custom report details, not implemented
            0x10 => {}, // server links, not implemented
            else => {
                diag.report(
                    error.BadPacketId,
                    "packet",
                    "bad packet id in configuration state: 0x{X:02}",
                    .{@as(u32, @intCast(configuration_packet.id))},
                );
                return error.BadPacketId;
            },
        }
    }

    log.debug("switched to play state", .{});

    // now we're in configuration state
    // but we don't have any of those packets, so return error
    return error.PlayState;
}

fn dumpDiagReports(diag_state: *const craft_io.Diag.State) void {
    for (diag_state.reports.items) |diag_report| {
        log.warn("diag report: {}", .{diag_report});
    }
}
