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
                defer self.value.deinit();
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
            const bytesRequired: usize = @intCast(std.math.divCeil(u16, bitsRequired, 7));
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

        pub fn decode(_: std.mem.Allocator, reader: anytype) !Decoded(Self) {
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

fn CraftInt(i: type) type {
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

        pub fn decode(_: std.mem.Allocator, reader: anytype) !Decoded(Self) {
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

    const Self = @This();

    pub fn init(v: bool) Self {
        return .{ .value = v };
    }

    pub fn length(_: *const Self) usize {
        return 1;
    }

    pub fn encode(self: *const Self, writer: anytype) !usize {
        try writer.writeByte(if (self.value) 1 else 0);
        return 1;
    }

    pub fn decode(_: std.mem.Allocator, reader: anytype) !Decoded(Self) {
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

fn PossiblyOwnedSlice(comptime Component: type) type {
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
                .owned => |*o| o.allocator.free(o.data),
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

pub fn Composite(comptime Payload: type) type {
    return struct {
        payload: Payload,

        const Self = @This();

        pub fn init(payload: Payload) Self {
            return .{ .payload = payload };
        }

        pub fn deinit(self: Self) void {
            if (std.meta.hasFn(Payload, "deinit")) {
                defer self.payload.deinit();
            } else {
                inline for (std.meta.fields(Payload)) |field| {
                    if (std.meta.hasFn(field.type, "deinit")) {
                        defer @field(self.payload, field.name).deinit();
                    }
                }
            }
        }

        pub fn length(self: *const Self) usize {
            if (std.meta.hasFn(Payload, "length")) {
                return self.payload.length();
            } else {
                var totalLength: usize = 0;
                inline for (std.meta.fields(Payload)) |field| {
                    if (std.meta.hasFn(field.type, "length")) {
                        totalLength += @field(self.payload, field.name).length();
                    } else {
                        @compileError("Field does not have length method... " ++ field.name);
                    }
                }
                return totalLength;
            }
        }

        pub fn decode(allocator: std.mem.Allocator, reader: anytype) !Decoded(Self) {
            if (std.meta.hasFn(Payload, "decode")) {
                return Payload.decode(allocator, reader);
            } else {
                var payload: Payload = undefined;
                var totalSize: usize = 0;
                inline for (std.meta.fields(Payload)) |field| {
                    if (std.meta.hasFn(field.type, "decode")) {
                        @field(payload, field.name) = (try field.type.decode(allocator, reader)).unbox(&totalSize);
                    } else {
                        @compileError("Field does not have decode method... " ++ field.name);
                    }
                }
                return .{ .value = .{ .payload = payload }, .bytes = totalSize };
            }
        }

        pub fn encode(self: *const Self, writer: anytype) !usize {
            if (std.meta.hasFn(Payload, "encode")) {
                return self.payload.encode(writer);
            } else {
                var totalSize: usize = 0;
                inline for (std.meta.fields(Payload)) |field| {
                    if (std.meta.hasFn(field.type, "encode")) {
                        totalSize += try @field(self.payload, field.name).encode(writer);
                    } else {
                        @compileError("Field does not have encode method... " ++ field.name);
                    }
                }
                return totalSize;
            }
        }

        pub fn format(self: Self, comptime fmt: []const u8, _: std.fmt.FormatOptions, writer: anytype) !void {
            if (fmt.len != 0) std.fmt.invalidFmtError(fmt, self);

            try writer.writeAll("{");
            const fields = std.meta.fields(Payload);
            if (fields.len > 1) {
                try writer.writeAll("\n");
            } else {
                try writer.writeAll(" ");
            }

            inline for (fields) |field| {
                if (fields.len > 1) {
                    try writer.writeAll("   ");
                }
                try std.fmt.format(writer, "{s} = {},", .{ field.name, @field(self.payload, field.name) });
                if (fields.len > 1) {
                    try writer.writeAll("\n");
                }
            }
            try writer.writeAll("}");
        }
    };
}

pub fn IntEnum(I: type, Payload: type) type {
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

        pub fn decode(allocator: std.mem.Allocator, reader: anytype) !Decoded(Self) {
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

pub fn CountedArray(Counter: type, Payload: type) type {
    return struct {
        items: PossiblyOwnedSlice(Payload),

        const Self = @This();

        pub fn init(items: []const Payload) Self {
            return .{ .items = .{ .borrowed = items } };
        }

        pub fn deinit(self: Self) void {
            defer self.items.deinit();
        }

        pub fn length(self: *const Self) usize {
            const counter = self.count();
            var size: usize = counter.length();
            for (self.constSlice()) |item| {
                size += item.length();
            }
            return size;
        }

        pub fn decode(allocator: std.mem.Allocator, reader: anytype) !Decoded(Self) {
            var bytes: usize = 0;
            const c: usize = @intCast((try Counter.decode(allocator, reader)).unbox(&bytes).value);

            var data = try std.ArrayList(Payload).initCapacity(allocator, c);
            defer data.deinit();

            if (Payload == u8) {
                try reader.readNoEof(data.addManyAsSliceAssumeCapacity(c));
                bytes += c;
            } else {
                for (0..c) |_| {
                    try data.append((try Payload.decode(allocator, reader)).unbox(&bytes));
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
