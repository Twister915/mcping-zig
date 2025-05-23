const std = @import("std");
const CraftConn = @import("CraftConn.zig");
const packets = @import("packets.zig");
const UUID = @import("UUID.zig");
const craft_chat = @import("chat.zig");
const draw = @import("draw.zig");

pub const std_options: std.Options = .{
    .log_level = .debug,
};

pub fn main() !void {
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
            handleTarget(allocator, "us.hypixel.net");
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

fn pingPrint(parent_allocator: std.mem.Allocator, target: Target) !void {
    var arena_allocator = std.heap.ArenaAllocator.init(parent_allocator);
    defer arena_allocator.deinit();

    const allocator = arena_allocator.allocator();

    const response = try ping(target, &arena_allocator);

    var bash_str_buf = std.ArrayList(u8).init(allocator);
    try craft_chat.writeBash(
        response.status.description,
        .{ .translate_traditional = true },
        .{},
        bash_str_buf.writer(),
    );

    std.debug.print("{s}\n", .{bash_str_buf.items});

    if (response.status.favicon) |favicon_raw| {
        const favicon_decoded = try favicon_raw.decode(allocator);
        const favicon_printer = try draw.FaviconPrinter.init(
            favicon_decoded,
            .{},
            arena_allocator.allocator(),
        );

        var favicon_printed_buf = std.ArrayList(u8).init(allocator);
        try favicon_printer.draw(favicon_printed_buf.writer());
        std.debug.print("{s}\n", .{favicon_printed_buf.items});
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

fn ping(target: Target, arena_allocator: *std.heap.ArenaAllocator) !PingResponse {
    var conn = try CraftConn.connect(arena_allocator.allocator(), target.host, target.port);
    defer conn.deinit(); // <-- close connection at the end of this function

    // state = handshaking
    // [tx]: Handshaking Packet :: 0x00
    _ = try conn.writePacket(0x00, packets.HandshakingPacket{
        .version = target.protocol_version,
        .address = target.host,
        .port = target.port,
        .next_state = .status,
    });

    // state = status
    // [tx]: Status Request Packet :: 0x00
    _ = try conn.writePacket(0x00, {});
    // [rx]: Status Response Packet :: 0x00
    const status_response_packet = try conn.readAndExpectPacket(
        0x00,
        packets.StatusResponsePacket,
        arena_allocator,
    );
    // [tx]: Status Ping Packet :: 0x01
    const ping_at_ms = std.time.milliTimestamp();
    _ = try conn.writePacket(0x01, packets.StatusPingPongPacket{ .timestamp = ping_at_ms });

    // [rx]: Status Pong Packet : 0x01
    const pong_packet = try conn.readAndExpectPacket(0x01, packets.StatusPingPongPacket, arena_allocator);
    const latency_ms: ?i64 = if (pong_packet.timestamp == ping_at_ms) std.time.milliTimestamp() - pong_packet.timestamp else null;
    return .{
        .status = status_response_packet.status,
        .latency_ms = latency_ms,
    };
}
