const std = @import("std");

// container for values which were decoded from a decode function
//
// returns the value which was decoded and how many bytes were read for that value
//
pub fn Decoded(comptime Target: type) type {
    return struct {
        value: Target,
        bytes: usize,

        const Self = @This();

        // potentially calls into deinit of the value
        pub fn deinit(self: Self) void {
            if (std.meta.hasFn(Target, "deinit")) {
                self.value.deinit();
            }
        }

        // quickly get the value out of this Decoded struct, optionally counting the bytes
        // in the passed ptr
        pub fn unbox(self: Self, sizeCounter: ?*usize) Target {
            if (sizeCounter) |ptr| {
                ptr.* += self.bytes;
            }

            return self.value;
        }

        pub fn format(self: Self, comptime fmt: []const u8, _: std.fmt.FormatOptions, writer: anytype) !void {
            try std.fmt.format(writer, fmt, .{self.value});
        }
    };
}

// VarInt / VarLong algorthim, generalized
// argument = the number of bits (32 = int, 64 = long)
fn VarNum(comptime Bits: u16) type {
    return struct {
        pub const BitSize = Bits;
        pub const ByteSize: usize = @intCast(std.math.divCeil(u16, BitSize, 7) catch @compileError("failed to divide BitSize by 7"));
        pub const Int = std.meta.Int(.signed, Bits);
        const BitCounter = std.meta.Int(.unsigned, std.math.log2_int_ceil(u16, Bits));
        const Self = @This();

        value: Int,

        pub fn init(i: Int) Self {
            return .{ .value = i };
        }

        pub fn length(self: *const Self) usize {
            const bitsRequired: u16 = Bits - @clz(self.value);
            const bytesRequired: usize = @intCast(std.math.divCeil(u16, bitsRequired, 7) catch unreachable);
            if (bytesRequired == 0) {
                return 1;
            } else {
                return bytesRequired;
            }
        }

        pub fn encode(self: *const Self, writer: anytype) !usize {
            var buf: [ByteSize]u8 = undefined;
            var toWrite: Int = self.value;
            var bytesWritten: usize = 0;
            while (true) {
                var byte: u8 = @intCast(toWrite & 0x7F);
                toWrite >>= 7;
                const hasMore = toWrite != 0;
                if (hasMore) {
                    byte |= 0x80;
                }
                buf[bytesWritten] = byte;
                bytesWritten += 1;
                if (hasMore) {
                    if (bytesWritten >= ByteSize) {
                        return error.VarNumTooLarge;
                    }
                } else {
                    try writer.writeAll(buf[0..bytesWritten]);
                    return bytesWritten;
                }
            }
        }

        pub fn decode(_: std.mem.Allocator, reader: anytype, _: usize) !Decoded(Self) {
            var bitsRead: BitCounter = 0;
            var value: Int = 0;
            var bytesRead: usize = 0;
            while (true) {
                const byte: Int = @intCast(try reader.readByte());
                value |= (byte & 0x7F) << bitsRead;
                bitsRead += 7;
                bytesRead += 1;
                if (byte & 0x80 == 0) {
                    return .{
                        .value = .{ .value = value },
                        .bytes = bytesRead,
                    };
                }

                if (bitsRead >= Bits) {
                    return error.VarNumTooLarge;
                }
            }
        }

        pub fn format(self: Self, comptime fmt: []const u8, _: std.fmt.FormatOptions, writer: anytype) !void {
            if (fmt.len != 0) std.fmt.invalidFmtError(fmt, self);
            try std.fmt.format(writer, "{}", .{self.value});
        }
    };
}

pub const VarInt = VarNum(32);
pub const VarLong = VarNum(64);

fn CraftInt(comptime i: type) type {
    return struct {
        value: Int,

        pub const Int = i;

        const Self = @This();
        const Length = @sizeOf(Int);

        pub fn init(v: Int) Self {
            return .{ .value = v };
        }

        pub fn length(_: *const Self) usize {
            return Length;
        }

        pub fn encode(self: *const Self, writer: anytype) !usize {
            try writer.writeInt(Int, self.value, .big);
            return Length;
        }

        pub fn decode(_: std.mem.Allocator, reader: anytype, _: usize) !Decoded(Self) {
            return .{ .bytes = Length, .value = .{ .value = try reader.readInt(Int, .big) } };
        }

        pub fn format(self: Self, comptime fmt: []const u8, _: std.fmt.FormatOptions, writer: anytype) !void {
            if (fmt.len != 0) std.fmt.invalidFmtError(fmt, self);
            try std.fmt.format(writer, "{}", .{self.value});
        }
    };
}

pub const Long = CraftInt(i64);
pub const UShort = CraftInt(u16);
pub const UByte = CraftInt(u8);

pub const Bool = struct {
    value: bool,

    pub const ByteSize: usize = 1;
    const Self = @This();

    pub fn init(v: bool) Self {
        return .{ .value = v };
    }

    pub fn length(_: *const Self) usize {
        return ByteSize;
    }

    pub fn encode(self: *const Self, writer: anytype) !usize {
        try writer.writeByte(if (self.value) 1 else 0);
        return ByteSize;
    }

    pub fn decode(_: std.mem.Allocator, reader: anytype, _: usize) !Decoded(Self) {
        return .{
            .bytes = 1,
            .value = .{
                .value = switch (try reader.readByte()) {
                    0 => false,
                    1 => true,
                    else => return error.UnexpectedBoolByte,
                },
            },
        };
    }

    pub fn format(self: Self, comptime fmt: []const u8, _: std.fmt.FormatOptions, writer: anytype) !void {
        if (fmt.len != 0) std.fmt.invalidFmtError(fmt, self);
        try writer.writeAll(if (self.value) "true" else "false");
    }
};

pub fn PossiblyOwnedSlice(comptime Component: type) type {
    const Owned = struct {
        data: []Component,
        allocator: std.mem.Allocator,
    };

    return union(enum) {
        owned: Owned,
        borrowed: []const Component,

        const Self = @This();

        pub fn deinit(self: Self) void {
            switch (self) {
                .owned => |*o| {
                    // deinit each item
                    if (std.meta.hasFn(Component, "deinit")) {
                        for (o.data) |item| {
                            item.deinit();
                        }
                    }

                    // free the memory where each item lives
                    o.allocator.free(o.data);
                },
                else => {},
            }
        }

        pub fn toOwned(self: Self, allocator: std.mem.Allocator) !Owned {
            switch (self) {
                .owned => |o| return o,
                .borrowed => |data| {
                    const duped = try allocator.dupe(Component, data);
                    return .{ .data = duped, .allocator = allocator };
                },
            }
        }

        pub fn constSlice(self: *const Self) []const Component {
            return switch (self.*) {
                .owned => |*o| o.data,
                .borrowed => |data| data,
            };
        }

        pub fn format(self: Self, comptime fmt: []const u8, _: std.fmt.FormatOptions, writer: anytype) !void {
            if (fmt.len != 0) std.fmt.invalidFmtError(fmt, self);
            try std.fmt.format(writer, "{}", .{self.constSlice()});
        }
    };
}

pub const String = CountedArray(VarInt, u8);

test "encode string" {
    const testData = "hello world";

    const craftStr = String.init(testData);
    defer craftStr.deinit();

    var buf = std.ArrayList(u8).init(std.testing.allocator);
    defer buf.deinit();

    const bytesWritten = try craftStr.encode(buf.writer());
    try std.testing.expectEqual(testData.len + 1, bytesWritten);
    try std.testing.expectEqualSlices(u8, &.{
        0x0B, // 11
        0x68, 0x65, 0x6C, 0x6C, 0x6F, // hello
        0x20, // space
        0x77, 0x6F, 0x72, 0x6C, 0x64, // world
    }, buf.items);
}

test "decode string" {
    const testData: []const u8 = &.{
        0x0B, // 11
        0x68, 0x65, 0x6C, 0x6C, 0x6F, // hello
        0x20, // space
        0x77, 0x6F, 0x72, 0x6C, 0x64, // world
    };

    var stream = std.io.fixedBufferStream(testData);
    const reader = stream.reader();

    const decoded = try String.decode(std.testing.allocator, reader);
    defer decoded.deinit();

    try std.testing.expectEqual(testData.len, decoded.bytes);
    try std.testing.expectEqualStrings("hello world", decoded.value.constSlice());
}

pub fn Struct(comptime Pld: type) type {
    return struct {
        pub fn deinit(self: Pld) void {
            inline for (std.meta.fields(Pld)) |field| {
                if (std.meta.hasFn(field.type, "deinit")) {
                    @field(self, field.name).deinit();
                }
            }
        }

        pub fn length(self: *const Pld) usize {
            var totalLength: usize = 0;
            inline for (std.meta.fields(Pld)) |field| {
                totalLength += @field(self, field.name).length();
            }
            return totalLength;
        }

        pub fn decode(allocator: std.mem.Allocator, reader: anytype, origBytesLeft: usize) !Decoded(Pld) {
            var bytesLeft = origBytesLeft;
            var decoded: Pld = undefined;
            var bytesRead: usize = 0;
            inline for (std.meta.fields(Pld)) |field| {
                const fieldDecoded: Decoded(field.type) = try field.type.decode(allocator, reader, bytesLeft);
                bytesRead += fieldDecoded.bytes;
                bytesLeft -= fieldDecoded.bytes;
                @field(decoded, field.name) = fieldDecoded.value;
            }
            return .{ .bytes = bytesRead, .value = decoded };
        }

        pub fn encode(self: *const Pld, writer: anytype) !usize {
            var totalSize: usize = 0;
            inline for (std.meta.fields(Pld)) |field| {
                totalSize += try @field(self, field.name).encode(writer);
            }
            return totalSize;
        }

        pub fn format(self: Pld, comptime fmt: []const u8, _: std.fmt.FormatOptions, writer: anytype) !void {
            if (fmt.len != 0) std.fmt.invalidFmtError(fmt, self);

            try writer.writeAll("{");
            const fields = std.meta.fields(Pld);
            if (fields.len > 1) {
                try writer.writeAll("\n");
            } else {
                try writer.writeAll(" ");
            }

            inline for (fields) |field| {
                if (fields.len > 1) {
                    try writer.writeAll("   ");
                }
                try std.fmt.format(writer, "{s} = {},", .{ field.name, @field(self, field.name) });
                if (fields.len > 1) {
                    try writer.writeAll("\n");
                }
            }
            try writer.writeAll("}");
        }
    };
}

pub fn IntEnum(
    comptime I: type,
    comptime Payload: type,
) type {
    return struct {
        value: Enum,

        const Self = @This();
        pub const Enum = Payload;

        pub fn init(v: Enum) Self {
            return .{ .value = v };
        }

        pub fn length(self: *const Self) usize {
            const ctr: I = I.init(@intFromEnum(self.value));
            return ctr.length();
        }

        pub fn decode(allocator: std.mem.Allocator, reader: anytype, _: usize) !Decoded(Self) {
            var size: usize = 0;
            const decoded: Enum = std.meta.intToEnum((try I.decode(allocator, reader)).unbox(&size)) catch {
                return error.InvalidEnumVariant;
            };
            return .{ .value = .{ .value = decoded }, .bytes = size };
        }

        pub fn encode(self: *const Self, writer: anytype) !usize {
            const ctr: I = I.init(@intFromEnum(self.value));
            return ctr.encode(writer);
        }

        pub fn format(self: Self, comptime fmt: []const u8, _: std.fmt.FormatOptions, writer: anytype) !void {
            if (fmt.len != 0) std.fmt.invalidFmtError(fmt, self);
            try std.fmt.format(writer, ".{s} ({d})", .{
                @tagName(self.value),
                @intFromEnum(self.value),
            });
        }
    };
}

pub fn CountedArray(
    comptime Counter: type,
    comptime Payload: type,
) type {
    return struct {
        items: PossiblyOwnedSlice(Payload),

        const Self = @This();

        pub fn init(items: []const Payload) Self {
            return .{ .items = .{ .borrowed = items } };
        }

        pub fn deinit(self: Self) void {
            self.items.deinit();
        }

        pub fn length(self: *const Self) usize {
            const counter = self.count();
            var size: usize = counter.length();
            for (self.constSlice()) |item| {
                size += item.length();
            }
            return size;
        }

        pub fn decode(allocator: std.mem.Allocator, reader: anytype, origBytesLeft: usize) !Decoded(Self) {
            var bytes: usize = 0;
            var bytesLeft: usize = origBytesLeft;
            const counterDecoded: Decoded(Counter) = try Counter.decode(allocator, reader, origBytesLeft);
            bytes += counterDecoded.bytes;
            bytesLeft -= counterDecoded.bytes;
            const c: usize = @intCast(counterDecoded.value.value);

            var data = try std.ArrayList(Payload).initCapacity(allocator, c);
            defer data.deinit();

            if (Payload == u8) {
                try reader.readNoEof(data.addManyAsSliceAssumeCapacity(c));
                bytes += c;
            } else {
                for (0..c) |_| {
                    const itemDecoded: Decoded(Payload) = try Payload.decode(allocator, reader, bytesLeft);
                    try data.append(itemDecoded.value);
                    bytes += itemDecoded.bytes;
                    bytesLeft -= itemDecoded.bytes;
                }
            }

            return .{
                .value = .{
                    .items = .{
                        .owned = .{
                            .data = try data.toOwnedSlice(),
                            .allocator = allocator,
                        },
                    },
                },
                .bytes = bytes,
            };
        }

        pub fn encode(self: *const Self, writer: anytype) !usize {
            var written: usize = 0;
            written += try self.count().encode(writer);
            const slice = self.constSlice();
            if (Payload == u8) {
                try writer.writeAll(slice);
                written += slice.len;
            } else {
                for (self.constSlice()) |item| {
                    written += try item.encode(writer);
                }
            }
            return written;
        }

        pub fn count(self: *const Self) Counter {
            return .init(@intCast(self.constSlice().len));
        }

        pub fn constSlice(self: *const Self) []const Payload {
            return self.items.constSlice();
        }

        pub fn borrowed(self: *const Self) Self {
            return switch (self.items) {
                .borrowed => self.*,
                .owned => .init(self.constSlice()),
            };
        }

        pub fn format(self: Self, comptime fmt: []const u8, _: std.fmt.FormatOptions, writer: anytype) !void {
            if (fmt.len != 0) std.fmt.invalidFmtError(fmt, self);
            const s = self.constSlice();
            if (Payload == u8) {
                try writer.writeAll("\"");
                try std.fmt.format(writer, "{s}", .{s});
                try writer.writeAll("\"");
            } else {
                try std.fmt.format(writer, "({d})[", .{s.len});
                for (s) |item| {
                    try std.fmt.format(writer, "{}, ", .{item});
                }
                try writer.writeAll("]");
            }
        }
    };
}

pub fn RestOfPacketArray(comptime Payload: type) type {
    return struct {
        items: PossiblyOwnedSlice(Payload),

        const Self = @This();

        pub fn init(items: []const Payload) Self {
            return .{ .items = .{ .borrowed = items } };
        }

        pub fn deinit(self: Self) void {
            self.items.deinit();
        }

        pub fn length(self: *const Self) usize {
            var l: usize = 0;
            for (self.constSlice()) |item| {
                l += item.length();
            }
            return l;
        }

        pub fn decode(allocator: std.mem.Allocator, reader: anytype, origBytesLeft: usize) !Decoded(Self) {
            var data = std.ArrayList(Payload).init(allocator);
            defer data.deinit();

            var bytesRead: usize = 0;
            if (Payload == u8) {
                try reader.readNoEof(try data.addManyAsSlice(origBytesLeft));
                bytesRead += origBytesLeft;
            } else {
                var bytesLeft: usize = origBytesLeft;
                while (bytesLeft > 0) {
                    const itemDecoded: Decoded(Payload) = try Payload.decode(allocator, reader, bytesLeft);
                    bytesLeft -= itemDecoded.bytes;
                    bytesRead += itemDecoded.bytes;
                    data.append(itemDecoded.value);
                }
            }

            return .{
                .value = .{
                    .items = .{
                        .owned = .{
                            .data = try data.toOwnedSlice(),
                            .allocator = allocator,
                        },
                    },
                },
                .bytes = bytesRead,
            };
        }

        pub fn encode(self: *const Self, writer: anytype) !usize {
            var bytes: usize = 0;

            const data = self.constSlice();
            if (Payload == u8) {
                try writer.writeAll(data);
                bytes = data.len;
            } else {
                for (data) |item| {
                    bytes += try item.encode(writer);
                }
            }

            return bytes;
        }

        pub fn borrowed(self: *const Self) Self {
            return switch (self.items.*) {
                .borrowed => self.*,
                .owned => .init(self.constSlice()),
            };
        }

        pub fn constSlice(self: *const Self) []const Payload {
            return self.items.constSlice();
        }

        pub fn format(self: Self, comptime fmt: []const u8, _: std.fmt.FormatOptions, writer: anytype) !void {
            if (fmt.len != 0) std.fmt.invalidFmtError(fmt, self);
            try std.fmt.format(writer, "{}", self.constSlice());
        }
    };
}

pub const RemainingBytes = RestOfPacketArray(u8);

pub const UUID = struct {
    pub const ByteSize: usize = 16;

    raw: [ByteSize]u8,

    pub fn fromStr(repr: []const u8) !UUID {
        return .{ .raw = try Parser.parse(repr) };
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

    pub fn length(_: *const UUID) usize {
        return ByteSize;
    }

    pub fn encode(uuid: *const UUID, writer: anytype) !usize {
        try writer.writeAll(&uuid.raw);
        return ByteSize;
    }

    pub fn decode(_: std.mem.Allocator, reader: anytype, _: usize) !Decoded(UUID) {
        var out: UUID = undefined;
        try reader.readNoEof(&out.raw);
        return .{ .bytes = ByteSize, .value = out };
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
                chars[1] = hexCharFor(@intCast(b & 0xF));
                chars[0] = hexCharFor(@intCast((b >> 4) & 0xF));
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

            fn hexCharFor(hb: u4) u8 {
                if (hb < 10) {
                    return @as(u8, @intCast(hb)) + '0';
                } else {
                    return @as(u8, @intCast(hb - 10)) + 'a';
                }
            }
        };
    }

    const Parser = struct {
        input: []const u8,

        fn parse(input: []const u8) ![16]u8 {
            var parser: Parser = .{ .input = input };
            var out: [ByteSize]u8 = undefined;
            try parser.consumeGroup(out[0..4]);
            const hasHyphens = try parser.consumeHyphen(true);
            try parser.consumeGroup(out[4..6]);
            if (hasHyphens) {
                _ = try parser.consumeHyphen(false);
            }
            try parser.consumeGroup(out[6..8]);
            if (hasHyphens) {
                _ = try parser.consumeHyphen(false);
            }
            try parser.consumeGroup(out[8..10]);
            if (hasHyphens) {
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
                    if (pc != '-' and decodeHexChar(pc) != null) {
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
            return decodeHexChar(try parser.consumeChar()) orelse error.InvalidHexChar;
        }

        fn decodeHexChar(c: u8) ?u4 {
            return switch (c) {
                '0'...'9' => @intCast(c - '0'),
                'a'...'f' => @as(u4, @intCast(c - 'a')) + 10,
                'A'...'F' => @as(u4, @intCast(c - 'A')) + 10,
                else => null,
            };
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
    const bytes = try id0.encode(buf.writer());
    try std.testing.expectEqual(UUID.ByteSize, bytes);
    try std.testing.expectEqualStrings(&id0.raw, buf.items);
}

pub fn Optional(comptime Payload: type) type {
    return union(enum) {
        some: Payload,
        none,

        const Self = @This();

        pub fn init(pld: Payload) Self {
            return .{ .some = pld };
        }

        pub fn deinit(self: Self) void {
            if (std.meta.hasFn(Payload, "deinit")) {
                switch (self) {
                    .some => |pld| {
                        pld.deinit();
                    },
                    .none => {},
                }
            }
        }

        pub fn encode(self: *const Self, writer: anytype) !usize {
            var bytes: usize = 0;
            switch (self.*) {
                .some => |*pld| {
                    const craftBool: Bool = .init(true);
                    bytes += try craftBool.encode(writer);
                    bytes += try pld.encode(writer);
                },
                .none => {
                    const craftBool: Bool = .init(false);
                    bytes += try craftBool.encode(writer);
                },
            }
            return bytes;
        }

        pub fn length(self: *const Self) usize {
            return Bool.ByteSize + switch (self.*) {
                .some => |*pld| pld.length(),
                .none => 0,
            };
        }

        pub fn decode(allocator: std.mem.Allocator, reader: anytype, bytesLeftOrig: usize) !Decoded(Self) {
            var bytesLeft: usize = bytesLeftOrig;
            var bytes: usize = 0;

            const presentDecoded: Decoded(Bool) = try Bool.decode(allocator, reader, bytesLeft);
            bytes += presentDecoded.bytes;

            if (presentDecoded.value.value) {
                bytesLeft -= presentDecoded.bytes;

                const payloadDecoded: Decoded(Payload) = try Payload.decode(allocator, reader, bytesLeft);
                bytes += payloadDecoded.bytes;
                bytesLeft -= payloadDecoded.bytes;
                return .{ .bytes = bytes, .value = .{ .some = payloadDecoded.value } };
            } else {
                return .{ .bytes = bytes, .value = .none };
            }
        }

        pub fn value(self: anytype) ?@TypeOf(&self.*.some) {
            return switch (self.*) {
                .some => |*pld| pld,
                .none => null,
            };
        }

        pub fn format(self: Self, comptime fmt: []const u8, _: std.fmt.FormatOptions, writer: anytype) !void {
            if (fmt.len != 0) std.fmt.invalidFmtError(fmt, self);
            try switch (self) {
                .some => |pld| std.fmt.format(writer, "{}", .{pld}),
                .none => writer.writeAll("null"),
            };
        }
    };
}

pub const Status = struct {
    pub const Version = struct {
        name: []const u8,
        protocol: i32,
    };

    pub const Players = struct {
        max: i32,
        online: i32,
        sample: []const PlayerSample,
    };

    pub const PlayerSample = struct {
        name: []const u8,
        uuid: []const u8,
    };

    version: Version,
    players: Players,
    description: []const u8,
    favicon: []const u8,
    enforcesSecureChat: bool,
};
