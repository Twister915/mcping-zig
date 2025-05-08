const std = @import("std");
const CraftConn = @import("CraftConn.zig");
const CraftPacket = @import("CraftPacket.zig");
const CraftTypes = @import("CraftTypes.zig");

pub const std_options: std.Options = .{
    .log_level = .debug,
};

pub fn main() !void {
    // 16k stack buffer for heap, should be fine since we only have to allocate the status string
    var buffer: [0x4000]u8 = undefined;
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
    if (std.mem.indexOfScalar(u8, raw, ':')) |rawPortIdx| {
        const portStartIdx = rawPortIdx + 1;
        if (raw.len > portStartIdx) {
            const rawPort = raw[rawPortIdx..];
            if (std.fmt.parseInt(u16, rawPort, 10) catch null) |parsed| {
                const host = raw[0..rawPortIdx];
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
        response.latencyMs,
        response.status.constSlice(),
    });
}

const Target = struct {
    protocolVersion: i32 = 769,
    host: []const u8,
    port: u16 = 25565,
};

const Profile = struct {
    username: []const u8,
    uuid: CraftTypes.UUID,
};

const PingResponse = struct {
    status: CraftTypes.CowSlice(u8),
    latencyMs: ?i64 = null,

    const Self = @This();

    fn deinit(self: Self) void {
        self.status.deinit();
    }
};

fn ping(allocator: std.mem.Allocator, target: Target) !PingResponse {
    var conn = try CraftConn.connect(allocator, target.host, target.port);
    defer conn.deinit();

    _ = try conn.writePacket(0x00, CraftPacket.HandshakingPacket{
        .version = @enumFromInt(target.protocolVersion),
        .address = .init(target.host),
        .port = target.port,
        .nextState = .status,
    });

    _ = try conn.writePacket(0x00, .{});
    const status = (try (try conn.readPacket()).decodeAs(allocator, CraftPacket.StatusResponsePacket)).status.items;

    const pingAtMs = std.time.milliTimestamp();
    _ = try conn.writePacket(0x01, CraftPacket.StatusPingPongPacket{
        .timestamp = pingAtMs,
    });

    const pongTs = (try (try conn.readPacket()).decodeAs(allocator, CraftPacket.StatusPingPongPacket)).timestamp;
    var out: PingResponse = .{ .status = status };
    if (pongTs == pingAtMs) {
        const pongRcvAt = std.time.milliTimestamp();
        out.latencyMs = pongRcvAt - pingAtMs;
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
        .version = @enumFromInt(target.protocolVersion),
        .nextState = .login,
    });

    // state = login

    // 0x00 LoginStart client ----> server
    _ = try conn.writePacket(0x00, CraftPacket.LoginStartPacket{
        .name = .init(profile.username),
        .uuid = profile.uuid,
    });

    login_state: while (true) {
        const loginPacket = try conn.readPacket();
        switch (@intFromEnum(loginPacket.id)) {
            0x00 => {
                const disconnectPacket = try loginPacket.decodeAs(allocator, CraftPacket.DisconnectPacket);
                defer disconnectPacket.deinit();

                std.debug.print("disconnected from {s} ---> {s}\n", .{ target.host, disconnectPacket.reason.constSlice() });
                return error.Disconnected;
            },
            0x01 => {
                // encryption request
                const encryptionRequestPacket = try loginPacket.decodeAs(allocator, CraftPacket.EncryptionRequestPacket);
                defer encryptionRequestPacket.deinit();

                std.debug.print("encryption requested ({}), not supported!\n", .{encryptionRequestPacket});
                return error.EncryptionRequested;
            },
            0x02 => {
                // login success
                const loginSuccessPacket = try loginPacket.decodeAs(allocator, CraftPacket.LoginSuccessPacket);
                defer loginSuccessPacket.deinit();

                // send login acknowledged
                _ = try conn.writePacket(0x03, .{});
                break :login_state;
            },
            0x03 => {
                // set compression
                const setCompressionPacket = try loginPacket.decodeAs(allocator, CraftPacket.SetCompressionPacket);

                try conn.setCompressionThreshold(@intCast(@intFromEnum(setCompressionPacket.threshold)));
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

                const pluginRequestPacket = try loginPacket.decodeAs(allocator, CraftPacket.LoginPluginRequestPacket);
                defer pluginRequestPacket.deinit();

                // login plugin response = 0x02
                _ = try conn.writePacket(0x02, CraftPacket.LoginPluginResponsePacket{
                    .messageId = pluginRequestPacket.messageId,
                    .data = .EMPTY,
                });
            },
            0x05 => {
                // cookie request
                // we don't have cookie storage yet, so let's just send back an empty cookie packet

                const cookieRequestPacket = try loginPacket.decodeAs(allocator, CraftPacket.LoginCookieRequestPacket);
                defer cookieRequestPacket.deinit();

                _ = try conn.writePacket(0x04, CraftPacket.LoginCookieResponsePacket{
                    .key = cookieRequestPacket.key.borrow(), // borrow so we don't deinit twice
                    .payload = .EMPTY,
                });
            },
            else => |otherId| {
                std.debug.print("bad packet id in login state 0x{x}\n", .{otherId});
                return error.BadPacketId;
            },
        }
    }

    // now we're in configuration state
    // but we don't have any of those packets, so return error
    return error.ConfigurationState;
}
