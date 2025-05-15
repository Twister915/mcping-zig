const std = @import("std");
const CraftConn = @import("CraftConn.zig");
const packets = @import("packets.zig");
const UUID = @import("UUID.zig");

pub const std_options: std.Options = .{
    .log_level = .debug,
};

pub fn main() !void {
    // 64k stack buffer for heap, should be fine since we only have to allocate the status string
    var gpa = std.heap.GeneralPurposeAllocator(.{
        .verbose_log = std.debug.runtime_safety,
    }).init;
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
            std.debug.print("error: must specify at least one target host\n", .{});
        }
    }
}

fn handleTarget(allocator: std.mem.Allocator, arg: []const u8) void {
    const target = targetFromArg(arg) catch |err| {
        std.debug.print("error parsing argument {s} -> {any}\n", .{ arg, err });
        return;
    };

    pingPrint(allocator, target) catch |err| {
        std.debug.print("error while pinging {s} -> {any}\n", .{ arg, err });
    };

    loginOffline(allocator, target, .{
        .username = "Notch",
        .uuid = .random(std.crypto.random),
    }) catch |err| {
        std.debug.print("error while logging into server {s} -> {any}\n", .{ arg, err });
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

fn pingPrint(allocator: std.mem.Allocator, target: Target) !void {
    var arena_allocator = std.heap.ArenaAllocator.init(allocator);
    defer arena_allocator.deinit();

    const response = try ping(target, &arena_allocator);
    std.debug.print("{?d}ms {s}\n", .{
        response.latency_ms,
        response.status,
    });
}

const Target = struct {
    protocol_version: i32 = 769,
    host: []const u8,
    port: u16 = 25565,
};

const Profile = struct {
    username: []const u8,
    uuid: UUID,
};

const PingResponse = struct {
    status: []const u8,
    latency_ms: ?i64 = null,
};

fn ping(target: Target, arena_allocator: *std.heap.ArenaAllocator) !PingResponse {
    const allocator = arena_allocator.allocator();
    var conn = try CraftConn.connect(allocator, target.host, target.port);
    defer conn.deinit();

    _ = try conn.writePacket(0x00, packets.HandshakingPacket{
        .version = target.protocol_version,
        .address = target.host,
        .port = target.port,
        .next_state = .status,
    });

    _ = try conn.writePacket(0x00, {});
    const status_response_packet = try (try conn.readPacket()).decodeAs(
        packets.StatusResponsePacket,
        arena_allocator,
    );
    const ping_at_ms = std.time.milliTimestamp();
    _ = try conn.writePacket(0x01, packets.StatusPingPongPacket{ .timestamp = ping_at_ms });

    const pong_ts: i64 = (try (try conn.readPacket()).decodeAs(packets.StatusPingPongPacket, arena_allocator)).timestamp;
    const pong_rcv_at = std.time.milliTimestamp();
    return .{
        .status = status_response_packet.status,
        .latency_ms = if (pong_ts == ping_at_ms) pong_rcv_at - pong_ts else null,
    };
}

fn loginOffline(allocator: std.mem.Allocator, target: Target, profile: Profile) !void {
    var conn = try CraftConn.connect(allocator, target.host, target.port);
    defer conn.deinit();

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
    });

    // state = login

    // 0x00 LoginStart client ----> server
    _ = try conn.writePacket(0x00, packets.LoginStartPacket{
        .name = profile.username,
        .uuid = profile.uuid,
    });

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

                std.debug.print("encryption requested ({}), not supported!\n", .{encryption_request_packet});
                return error.EncryptionRequested;
            },
            0x02 => {
                // login success
                // we skip decode because we don't use the data
                // const login_success_packet = try login_packet.decodeAs(packets.LoginSuccessPacket, &arena_allocator);
                // defer arena_allocator.reset(.retain_capacity);

                // send login acknowledged
                _ = try conn.writePacket(0x03, {});
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
                });
            },
            0x05 => {
                // cookie request
                // we don't have cookie storage yet, so let's just send back an empty cookie packet

                const cookie_request_packet = try login_packet.decodeAs(packets.LoginCookieRequestPacket, &arena_allocator);
                defer _ = arena_allocator.reset(.retain_capacity);

                _ = try conn.writePacket(0x04, packets.LoginCookieResponsePacket{
                    .key = cookie_request_packet.key, // borrow so we don't deinit twice
                    .payload = null,
                });
            },
            else => |other_id| {
                std.debug.print("bad packet id in login state 0x{x}\n", .{other_id});
                return error.BadPacketId;
            },
        }
    }

    // now we're in configuration state
    // but we don't have any of those packets, so return error
    return error.ConfigurationState;
}
