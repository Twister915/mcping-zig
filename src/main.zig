const std = @import("std");
const CraftConn = @import("CraftConn.zig");
const CraftPacket = @import("CraftPacket.zig");
const CraftTypes = @import("CraftTypes.zig");

pub const std_options: std.Options = .{
    .log_level = .debug,
};

pub fn main() !void {
    // 64k stack buffer for heap, should be fine since we only have to allocate the status string
    var buffer: [0x10000]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buffer);
    const allocator = fba.allocator();

    var any: bool = false;
    var args = std.process.args();
    _ = args.skip();
    while (args.next()) |arg| {
        const target = targetFromArg(arg) catch |err| {
            std.debug.print("error parsing argument {s} -> {any}\n", .{ arg, err });
            continue;
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

        any = true;
    }

    if (!any) {
        std.debug.print("error: must specify at least one target host\n", .{});
    }
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
    const response = try ping(allocator, target);
    defer response.deinit();

    std.debug.print("{?d}ms {s}\n", .{
        response.latency_ms,
        response.status_response_packet.status.constSlice(),
    });
}

const Target = struct {
    protocol_version: i32 = 769,
    host: []const u8,
    port: u16 = 25565,
};

const Profile = struct {
    username: []const u8,
    uuid: CraftTypes.UUID,
};

const PingResponse = struct {
    status_response_packet: CraftPacket.StatusResponsePacket,
    latency_ms: ?i64 = null,

    const Self = @This();

    fn deinit(self: Self) void {
        self.status_response_packet.deinit();
    }
};

fn ping(allocator: std.mem.Allocator, target: Target) !PingResponse {
    var conn = try CraftConn.connect(allocator, target.host, target.port);
    defer conn.deinit();

    _ = try conn.writePacket(0x00, CraftPacket.HandshakingPacket{
        .version = @enumFromInt(target.protocol_version),
        .address = .init(target.host),
        .port = target.port,
        .next_state = .status,
    });

    _ = try conn.writePacket(0x00, .{});
    // we return the strings in this response packet, so we don't deinit the packet here (let the )
    const status_response_packet = try (try conn.readPacket()).decodeAs(allocator, CraftPacket.StatusResponsePacket);

    const ping_at_ms = std.time.milliTimestamp();
    _ = try conn.writePacket(0x01, CraftPacket.StatusPingPongPacket{
        .timestamp = ping_at_ms,
    });

    const pong_ts = (try (try conn.readPacket()).decodeAs(allocator, CraftPacket.StatusPingPongPacket)).timestamp;
    var out: PingResponse = .{ .status_response_packet = status_response_packet };
    if (pong_ts == ping_at_ms) {
        const pong_rcv_at = std.time.milliTimestamp();
        out.latency_ms = pong_rcv_at - ping_at_ms;
    }
    return out;
}

fn loginOffline(allocator: std.mem.Allocator, target: Target, profile: Profile) !void {
    var conn = try CraftConn.connect(allocator, target.host, target.port);
    defer conn.deinit();
    // state = handshaking
    _ = try conn.writePacket(0x00, CraftPacket.HandshakingPacket{
        .address = .init(target.host),
        .port = target.port,
        .version = @enumFromInt(target.protocol_version),
        .next_state = .login,
    });

    // state = login

    // 0x00 LoginStart client ----> server
    _ = try conn.writePacket(0x00, CraftPacket.LoginStartPacket{
        .name = .init(profile.username),
        .uuid = profile.uuid,
    });

    login_state: while (true) {
        const login_packet = try conn.readPacket();
        switch (@intFromEnum(login_packet.id)) {
            0x00 => {
                const disconnect_packet = try login_packet.decodeAs(allocator, CraftPacket.DisconnectPacket);
                defer disconnect_packet.deinit();

                std.debug.print("disconnected from {s} ---> {s}\n", .{ target.host, disconnect_packet.reason.constSlice() });
                return error.Disconnected;
            },
            0x01 => {
                // encryption request
                const encryption_request_packet = try login_packet.decodeAs(allocator, CraftPacket.EncryptionRequestPacket);
                defer encryption_request_packet.deinit();

                std.debug.print("encryption requested ({}), not supported!\n", .{encryption_request_packet});
                return error.EncryptionRequested;
            },
            0x02 => {
                // login success
                const login_success_packet = try login_packet.decodeAs(allocator, CraftPacket.LoginSuccessPacket);
                defer login_success_packet.deinit();

                // send login acknowledged
                _ = try conn.writePacket(0x03, .{});
                break :login_state;
            },
            0x03 => {
                // set compression
                const set_compression_packet = try login_packet.decodeAs(allocator, CraftPacket.SetCompressionPacket);
                try conn.setCompressionThreshold(@intCast(@intFromEnum(set_compression_packet.threshold)));
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

                const ping_request_packet = try login_packet.decodeAs(allocator, CraftPacket.LoginPluginRequestPacket);
                defer ping_request_packet.deinit();

                // login plugin response = 0x02
                _ = try conn.writePacket(0x02, CraftPacket.LoginPluginResponsePacket{
                    .message_id = ping_request_packet.message_id,
                    .data = .EMPTY,
                });
            },
            0x05 => {
                // cookie request
                // we don't have cookie storage yet, so let's just send back an empty cookie packet

                const cookie_request_packet = try login_packet.decodeAs(allocator, CraftPacket.LoginCookieRequestPacket);
                defer cookie_request_packet.deinit();

                _ = try conn.writePacket(0x04, CraftPacket.LoginCookieResponsePacket{
                    .key = cookie_request_packet.key.borrow(), // borrow so we don't deinit twice
                    .payload = .EMPTY,
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
