const std = @import("std");
const util = @import("util.zig");

const UUID = @This();

pub const BYTES: usize = 16;

raw: [BYTES]u8,

pub fn fromStr(repr: []const u8) !UUID {
    return .{ .raw = try Parser.parse(repr) };
}

pub fn jsonParse(
    allocator: std.mem.Allocator,
    source: anytype,
    options: std.json.ParseOptions,
) !UUID {
    const str_parsed = try std.json.innerParse([]const u8, allocator, source, options);
    return fromStr(str_parsed) catch {
        return error.UnexpectedToken;
    };
}

pub fn jsonStringify(self: UUID, jw: anytype) !void {
    try jw.print("{s}", .{self});
}

pub fn random(rng: anytype) UUID {
    var out: UUID = undefined;
    rng.bytes(&out.raw);
    out.raw[6] &= 0x0f;
    out.raw[6] |= 0x40;
    out.raw[8] &= 0x3f;
    out.raw[8] |= 0x80;
    return out;
}

pub fn format(uuid: *const UUID, comptime fmt: []const u8, _: std.fmt.FormatOptions, writer: anytype) !void {
    if (fmt.len != 0) std.fmt.invalidFmtError(fmt, uuid);
    var emitter: Emitter(@TypeOf(writer)) = .{ .raw = &uuid.raw, .writer = writer };
    try emitter.emit();
}

fn Emitter(Writer: type) type {
    return struct {
        raw: []const u8,
        writer: Writer,
        hyphens: bool = true,

        const Self = @This();

        fn emit(self: *Self) !void {
            try self.emitGroup(4);
            try self.emitHyphen();
            try self.emitGroup(2);
            try self.emitHyphen();
            try self.emitGroup(2);
            try self.emitHyphen();
            try self.emitGroup(2);
            try self.emitHyphen();
            try self.emitGroup(6);
        }

        fn emitGroup(self: *Self, bytes: usize) !void {
            for (0..bytes) |_| {
                try self.emitByte();
            }
        }

        fn emitHyphen(self: *Self) !void {
            if (self.hyphens) {
                try self.writer.writeByte('-');
            }
        }

        fn emitByte(self: *Self) !void {
            const b = try self.consumeByte();
            var chars: [2]u8 = undefined;
            chars[1] = util.hexCharFor(@intCast(b & 0xF));
            chars[0] = util.hexCharFor(@intCast((b >> 4) & 0xF));
            try self.writer.writeAll(&chars);
        }

        fn consumeByte(self: *Self) !u8 {
            if (self.raw.len == 0) {
                return error.NotEnoughBytes;
            } else {
                const b = self.raw[0];
                self.raw = self.raw[1..];
                return b;
            }
        }
    };
}

const Parser = struct {
    input: []const u8,

    fn parse(input: []const u8) ![16]u8 {
        var parser: Parser = .{ .input = input };
        var out: [BYTES]u8 = undefined;
        try parser.consumeGroup(out[0..4]);
        const has_hyphens = try parser.consumeHyphen(true);
        try parser.consumeGroup(out[4..6]);
        if (has_hyphens) {
            _ = try parser.consumeHyphen(false);
        }
        try parser.consumeGroup(out[6..8]);
        if (has_hyphens) {
            _ = try parser.consumeHyphen(false);
        }
        try parser.consumeGroup(out[8..10]);
        if (has_hyphens) {
            _ = try parser.consumeHyphen(false);
        }
        try parser.consumeGroup(out[10..16]);
        if (parser.input.len != 0) {
            return error.ExpectedEOF;
        }
        return out;
    }

    fn consumeGroup(parser: *Parser, dest: []u8) !void {
        for (dest) |*d| {
            d.* = try parser.consumeHexByte();
        }
    }

    fn consumeHyphen(parser: *Parser, optional: bool) !bool {
        if (optional) {
            if (parser.peekChar()) |pc| {
                // next char is not a hyphen, but it is a valid hex char
                if (pc != '-' and util.decodeHexChar(pc) != null) {
                    return false;
                }
            }
        }

        if ((try parser.consumeChar()) != '-') {
            return error.ExpectedHyphen;
        } else {
            return true;
        }
    }

    fn consumeHexByte(parser: *Parser) !u8 {
        return (@as(u8, @intCast(try parser.consumeHexChar())) << 4) | @as(u8, @intCast(try parser.consumeHexChar()));
    }

    fn consumeHexChar(parser: *Parser) !u4 {
        return util.decodeHexChar(try parser.consumeChar()) orelse error.InvalidHexChar;
    }

    fn peekChar(parser: *Parser) ?u8 {
        if (parser.input.len == 0) {
            return null;
        } else {
            return parser.input[0];
        }
    }

    fn consumeChar(parser: *Parser) !u8 {
        if (parser.input.len == 0) {
            return error.UnexpectedEof;
        } else {
            const out = parser.input[0];
            parser.input = parser.input[1..];
            return out;
        }
    }
};

test "random uuid" {
    const id0 = UUID.random(std.crypto.random);
    std.debug.print("id = {}\n", .{id0});
}

test "parse uuid" {
    const id0 = try UUID.fromStr("a02c0615-2879-46db-8c4c-e7c7329d98d2");
    std.debug.print("id = {}\n", .{id0});
}

test "parse uuid no hyphens" {
    const id0 = try UUID.fromStr("a02c0615287946db8c4ce7c7329d98d2");
    std.debug.print("id = {}\n", .{id0});
}

test "encode uuid" {
    var buf = std.ArrayList(u8).init(std.testing.allocator);
    defer buf.deinit();

    const id0 = UUID.random(std.crypto.random);
    const bytes = try @import("io.zig").encode(id0, buf.writer(), std.testing.allocator, .{}, .{});
    try std.testing.expectEqual(UUID.BYTES, bytes);
    try std.testing.expectEqualStrings(&id0.raw, buf.items);
}
