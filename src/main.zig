const std = @import("std");
const CraftConn = @import("CraftConn.zig");
const CraftPacket = @import("CraftPacket.zig");

pub const std_options: std.Options = .{
    .log_level = .debug,
};

var gpa = std.heap.GeneralPurposeAllocator(.{}).init;
const allocator = gpa.allocator();

pub fn main() !void {
    var any: bool = false;
    var args = std.process.args();
    _ = args.skip();
    while (args.next()) |arg| {
        pingPrint(arg) catch |err| {
            std.debug.print("error while pinging {s} -> {any}\n", .{ arg, err });
        };
        any = true;
    }

    if (!any) {
        std.debug.print("error: must specify at least one target host\n", .{});
    }
}

fn pingPrint(raw: []const u8) !void {
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
    const responsePacket = try ping(target);
    defer responsePacket.deinit();

    std.debug.print("got {}\n", .{responsePacket});
}

const Target = struct {
    protocolVersion: i32 = 769,
    host: []const u8,
    port: u16 = 25565,
};

fn ping(target: Target) !CraftPacket.StatusResponsePacket {
    var conn = try CraftConn.connect(allocator, target.host, target.port);
    defer conn.deinit();

    _ = try conn.writePacket(.init(0x00), CraftPacket.HandshakingPacket, .init(.{
        .version = .init(target.protocolVersion),
        .address = .init(target.host),
        .port = .init(target.port),
        .nextState = .init(.status),
    }));

    _ = try conn.writePacket(.init(0x00), CraftPacket.EmptyPacket, .init(.{}));
    return (try (try conn.readPacket()).value.decodeAs(CraftPacket.StatusResponsePacket)).value;
}
