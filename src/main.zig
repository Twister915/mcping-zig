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
        pingPrint(allocator, arg) catch |err| {
            std.debug.print("error while pinging {s} -> {any}\n", .{ arg, err });
        };
        any = true;
    }

    if (!any) {
        std.debug.print("error: must specify at least one target host\n", .{});
    }
}

fn pingPrint(allocator: std.mem.Allocator, raw: []const u8) !void {
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

const PingResponse = struct {
    status: CraftTypes.PossiblyOwnedSlice(u8),
    latencyMs: ?i64 = null,

    const Self = @This();

    fn deinit(self: Self) void {
        self.status.deinit();
    }
};

fn ping(allocator: std.mem.Allocator, target: Target) !PingResponse {
    var conn = try CraftConn.connect(allocator, target.host, target.port);
    defer conn.deinit();

    _ = try conn.writePacket(.init(0x00), CraftPacket.HandshakingPacket{
        .version = .init(target.protocolVersion),
        .address = .init(target.host),
        .port = .init(target.port),
        .nextState = .init(.status),
    });

    _ = try conn.writePacket(.init(0x00), CraftPacket.EmptyPacket{});
    const status = (try (try conn.readPacket()).value.decodeAs(CraftPacket.StatusResponsePacket)).value.status.items;

    const pingAtMs = std.time.milliTimestamp();
    _ = try conn.writePacket(.init(0x01), CraftPacket.StatusPingPongPacket{
        .timestamp = .init(pingAtMs),
    });

    const pongTs = (try (try conn.readPacket()).value.decodeAs(CraftPacket.StatusPingPongPacket)).value.timestamp.value;
    var out: PingResponse = .{ .status = status };
    if (pongTs == pingAtMs) {
        const pongRcvAt = std.time.milliTimestamp();
        out.latencyMs = pongRcvAt - pingAtMs;
    }
    return out;
}
