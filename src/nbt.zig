const std = @import("std");
const craft_io = @import("io.zig");
const Diag = @import("Diag.zig");

pub const TagType = enum(u8) {
    end = 0,
    byte = 1,
    short = 2,
    int = 3,
    long = 4,
    float = 5,
    double = 6,
    byte_array = 7,
    string = 8,
    list = 9,
    compound = 10,
    int_array = 11,
    long_array = 12,

    fn decodeTag(type_id: TagType, reader: anytype, allocator: std.mem.Allocator, diag: Diag) DecodeError(@TypeOf(reader))!craft_io.Decoded(Tag) {
        switch (type_id) {
            .end => return .{
                .value = .end,
                .bytes_read = 0,
            },
            .byte => return .{
                .value = .{ .byte = @intCast(try reader.readByte()) },
                .bytes_read = 1,
            },
            .short => return .{
                .value = .{ .short = try reader.readInt(i16, .big) },
                .bytes_read = 2,
            },
            .int => return .{
                .value = .{ .int = try reader.readInt(i32, .big) },
                .bytes_read = 4,
            },
            .long => return .{
                .value = .{ .long = try reader.readInt(i64, .big) },
                .bytes_read = 8,
            },
            .float => return .{
                .value = .{ .float = @bitCast(try reader.readInt(u32, .big)) },
                .bytes_read = 4,
            },
            .double => return .{
                .value = .{ .double = @bitCast(try reader.readInt(u64, .big)) },
                .bytes_read = 8,
            },
            .byte_array => return decodeByteArrayTag(reader, allocator),
            .string => return decodeStringTag(reader, allocator),
            .list => return decodeListTag(reader, allocator, diag),
            .compound => return decodeCompoundTag(reader, allocator, diag),
            .int_array => return decodeIntArrayTag(reader, allocator),
            .long_array => return decodeLongArrayTag(reader, allocator),
        }
    }
};

pub const NbtDecodeError = error{DecodeBadData};

pub fn DecodeError(comptime Reader: type) type {
    return NbtDecodeError || Reader.NoEofError || std.mem.Allocator.Error || Diag.Error;
}

pub const Tag = union(TagType) {
    end,
    byte: i8,
    short: i16,
    int: i32,
    long: i64,
    float: f32,
    double: f64,
    byte_array: []const i8, // not a mistake... i8
    string: []const u8,
    list: List,
    compound: []const NamedTag,
    int_array: []const i32,
    long_array: []const i64,

    pub const List = union(TagType) {
        end,
        byte: ListField("byte"),
        short: ListField("short"),
        int: ListField("int"),
        long: ListField("long"),
        float: ListField("float"),
        double: ListField("double"),
        byte_array: ListField("byte_array"),
        string: ListField("string"),
        list: ListField("list"),
        compound: ListField("compound"),
        int_array: ListField("int_array"),
        long_array: ListField("long_array"),

        pub fn len(l: List) usize {
            return switch (l) {
                .end => 0,
                inline else => |pld| pld.len,
            };
        }

        pub fn iter(l: *const List) ListIter {
            return .{ .list = l };
        }

        fn ListField(comptime field_name: []const u8) type {
            return []const @FieldType(Tag, field_name);
        }
    };

    pub const ListIter = struct {
        list: *const List,
        index: usize = 0,

        pub fn next(iter: *ListIter) ?Tag {
            switch (iter.list.*) {
                .end => {},
                inline else => |slice, tag| {
                    if (iter.index < slice.len) {
                        const out = @unionInit(
                            Tag,
                            @tagName(tag),
                            slice[iter.index],
                        );
                        iter.index += 1;
                        return out;
                    }
                },
            }
            return null;
        }
    };

    pub const CraftEncoding: type = void;
    pub const CraftDecodeError: type = NbtDecodeError;

    pub fn craftDecode(
        reader: anytype,
        allocator: *std.heap.ArenaAllocator,
        diag: Diag,
        comptime encoding: void,
    ) !craft_io.Decoded(Tag) {
        _ = encoding;
        return decodeTag(reader, allocator.allocator(), diag);
    }

    pub fn craftEncode(
        tag: Tag,
        writer: anytype,
        allocator: std.mem.Allocator,
        diag: Diag,
        comptime encoding: void,
    ) !usize {
        _ = allocator;
        _ = encoding;
        _ = diag; // FIXME diag
        return encodeTag(tag, writer);
    }

    pub fn format(
        tag: Tag,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fmt;
        _ = options;

        try writer.writeAll("NBT_");
        try writer.writeAll(@tagName(@as(TagType, tag)));
        try writer.writeAll(": ");
        try formatPayload(tag, writer);
    }

    pub fn formatPayload(tag: Tag, writer: anytype) !void {
        switch (tag) {
            .end => {},
            .string => |str| try std.fmt.format(writer, "\"{s}\"", .{str}),
            inline .byte,
            .short,
            .int,
            .long,
            .float,
            .double,
            => |number| try std.fmt.format(writer, "{d}", .{number}),
            inline .byte_array,
            .int_array,
            .long_array,
            => |items| try std.fmt.format(writer, "{any}", .{items}),
            .list => |l| {
                try writer.writeAll("[");
                const num_items = l.len();
                if (num_items > 0) {
                    const last_idx = num_items - 1;
                    var idx: usize = 0;
                    var iter = l.iter();
                    while (iter.next()) |item| {
                        try std.fmt.format(writer, "{}", .{item});
                        if (last_idx != idx) {
                            try writer.writeAll(", ");
                        }
                        idx += 1;
                    }
                }
                try writer.writeAll("]");
            },
            .compound => |named_tags| {
                try writer.writeAll("[");
                if (named_tags.len > 0) {
                    const last_idx = named_tags.len - 1;
                    for (named_tags, 0..) |item, idx| {
                        try std.fmt.format(writer, "{}", .{item});
                        if (last_idx != idx) {
                            try writer.writeAll(", ");
                        }
                    }
                }
                try writer.writeAll("]");
            },
        }
    }
};

pub const NamedTag = struct {
    name: []const u8,
    tag: Tag,

    pub const CraftEncoding: type = struct {
        root_has_no_name: bool = true,
    };

    pub const CraftDecodeError: type = NbtDecodeError;

    pub fn craftDecode(
        reader: anytype,
        allocator: *std.heap.ArenaAllocator,
        diag: Diag,
        comptime encoding: CraftEncoding,
    ) !craft_io.Decoded(NamedTag) {
        if (encoding.root_has_no_name) {
            const dcd = try decodeTag(reader, allocator.allocator(), diag);
            return .{
                .value = .{
                    .name = "",
                    .tag = dcd.value,
                },
                .bytes_read = dcd.bytes_read,
            };
        } else {
            return decodeNamedTag(reader, allocator.allocator(), diag);
        }
    }

    pub fn craftEncode(
        named_tag: NamedTag,
        writer: anytype,
        allocator: std.mem.Allocator,
        diag: Diag,
        comptime encoding: CraftEncoding,
    ) !usize {
        _ = allocator;
        _ = diag; // FIXME diag
        if (encoding.root_has_no_name) {
            return encodeTag(named_tag.tag, writer);
        } else {
            return encodeNamedTag(named_tag, writer);
        }
    }

    pub fn format(
        named_tag: NamedTag,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fmt;
        _ = options;

        try std.fmt.format(
            writer,
            "NBT_{s}(\"{s}\"): ",
            .{ @tagName(@as(TagType, named_tag.tag)), named_tag.name },
        );
        try named_tag.tag.formatPayload(writer);
    }
};

fn encodeNamedTag(named_tag: NamedTag, writer: anytype) !usize {
    var bytes_written: usize = 0;
    bytes_written += try encodeTagType(@as(TagType, named_tag.tag), writer);
    if (named_tag.tag != .end) {
        bytes_written += try encodeString(named_tag.name, writer);
        bytes_written += try encodeTagPayload(named_tag.tag, writer);
    }
    return bytes_written;
}

fn decodeNamedTag(reader: anytype, allocator: std.mem.Allocator, diag: Diag) !craft_io.Decoded(NamedTag) {
    var bytes_read: usize = 0;
    const tag_id = (try decodeTagType(reader, diag)).unwrap(&bytes_read);
    if (tag_id == .end) {
        return .{
            .value = .{
                .name = "",
                .tag = .end,
            },
            .bytes_read = bytes_read,
        };
    }

    const name = (try decodeString(reader, allocator)).unwrap(&bytes_read);
    const tag = (try tag_id.decodeTag(reader, allocator, diag)).unwrap(&bytes_read);
    return .{
        .value = .{
            .name = name,
            .tag = tag,
        },
        .bytes_read = bytes_read,
    };
}

fn decodeTag(reader: anytype, allocator: std.mem.Allocator, diag: Diag) !craft_io.Decoded(Tag) {
    var bytes_read: usize = 0;
    const tag_type = (try decodeTagType(reader, diag)).unwrap(&bytes_read);
    const tag = (try tag_type.decodeTag(reader, allocator, diag)).unwrap(&bytes_read);
    return .{ .value = tag, .bytes_read = bytes_read };
}

fn encodeTag(tag: Tag, writer: anytype) !usize {
    var bytes_written: usize = 0;
    bytes_written += try encodeTagType(@as(TagType, tag), writer);
    bytes_written += try encodeTagPayload(tag, writer);
    return bytes_written;
}

fn encodeTagPayload(tag: Tag, writer: anytype) !usize {
    switch (tag) {
        .end => return 0,
        .byte => |b| {
            try writer.writeByte(@intCast(b));
            return 1;
        },
        .short => |s| {
            try writer.writeInt(i16, s, .big);
            return 2;
        },
        .int => |i| {
            try writer.writeInt(i32, i, .big);
            return 4;
        },
        .long => |l| {
            try writer.writeInt(i64, l, .big);
            return 8;
        },
        .float => |f| {
            try writer.writeInt(u32, @as(u32, @bitCast(f)), .big);
            return 4;
        },
        .double => |d| {
            try writer.writeInt(u64, @as(u64, @bitCast(d)), .big);
            return 8;
        },
        .byte_array => |bytes| return encodeLengthPrefixedBytes(i32, @ptrCast(bytes), writer),
        .string => |str| return encodeString(str, writer),
        .list => |l| return encodeList(l, writer),
        .compound => |c| return encodeCompound(c, writer),
        .int_array => |ints| return encodeIntArray(ints, writer),
        .long_array => |longs| return encodeIntArray(longs, writer),
    }
}

fn decodeTagType(reader: anytype, diag: Diag) !craft_io.Decoded(TagType) {
    const tag_byte = try reader.readByte();
    const tag_type: TagType = std.meta.intToEnum(TagType, tag_byte) catch {
        diag.report(
            error.UnknownNbtType,
            @typeName(TagType),
            "decoded bad tag byte 0x{X:02}",
            .{tag_byte},
        );
        return error.DecodeBadData;
    };
    return .{ .bytes_read = 1, .value = tag_type };
}

fn encodeTagType(tag_type: TagType, writer: anytype) !usize {
    try writer.writeByte(@as(u8, @intFromEnum(tag_type)));
    return 1;
}

fn decodeByteArrayTag(reader: anytype, allocator: std.mem.Allocator) !craft_io.Decoded(Tag) {
    const bytes_dcd = try decodeLengthPrefixedBytes(i32, reader, allocator);
    return .{
        .value = .{ .byte_array = @ptrCast(bytes_dcd.value) },
        .bytes_read = bytes_dcd.bytes_read,
    };
}

fn decodeStringTag(reader: anytype, allocator: std.mem.Allocator) !craft_io.Decoded(Tag) {
    const str_dcd = try decodeString(reader, allocator);
    return .{
        .value = .{ .string = str_dcd.value },
        .bytes_read = str_dcd.bytes_read,
    };
}

fn decodeString(reader: anytype, allocator: std.mem.Allocator) !craft_io.Decoded([]const u8) {
    return decodeLengthPrefixedBytes(u16, reader, allocator);
}

fn encodeString(str: []const u8, writer: anytype) !usize {
    return encodeLengthPrefixedBytes(u16, str, writer);
}

fn decodeLengthPrefixedBytes(comptime Counter: type, reader: anytype, allocator: std.mem.Allocator) !craft_io.Decoded([]const u8) {
    var bytes_read: usize = 0;
    const counter: usize = @intCast(try reader.readInt(Counter, .big));
    bytes_read += @sizeOf(Counter);
    const buf = try allocator.alloc(u8, counter);
    errdefer allocator.free(buf);

    try reader.readNoEof(buf);
    bytes_read += counter;
    return .{ .value = buf, .bytes_read = bytes_read };
}

fn encodeLengthPrefixedBytes(comptime Counter: type, data: []const u8, writer: anytype) !usize {
    var bytes_written: usize = 0;
    try writer.writeInt(Counter, @as(Counter, @intCast(data.len)), .big);
    bytes_written += @sizeOf(Counter);
    try writer.writeAll(data);
    bytes_written += data.len;
    return bytes_written;
}

fn decodeListTag(reader: anytype, allocator: std.mem.Allocator, diag: Diag) !craft_io.Decoded(Tag) {
    const list_decoded = try decodeList(reader, allocator, diag);
    return .{
        .value = .{ .list = list_decoded.value },
        .bytes_read = list_decoded.bytes_read,
    };
}

fn decodeList(reader: anytype, allocator: std.mem.Allocator, diag: Diag) !craft_io.Decoded(Tag.List) {
    var bytes_read: usize = 0;
    const contents_type_id = (try decodeTagType(reader, try diag.child(.tag))).unwrap(&bytes_read);

    switch (contents_type_id) {
        .end => return error.DecodeBadData,
        inline else => |type_id| {
            const list_length: usize = @intCast(try reader.readInt(i32, .big));
            bytes_read += 4; // i32

            const tag_name = @tagName(type_id);
            const ElemType: type = @FieldType(Tag, tag_name);
            const out: []ElemType = try allocator.alloc(ElemType, list_length);
            errdefer allocator.free(out);

            for (out, 0..) |*item, idx| {
                const item_dcd = try contents_type_id.decodeTag(reader, allocator, try diag.child(.{ .index = idx }));
                bytes_read += item_dcd.bytes_read;
                item.* = @field(item_dcd.value, tag_name);
            }
            return .{
                .value = @unionInit(Tag.List, tag_name, out),
                .bytes_read = bytes_read,
            };
        },
    }
}

fn encodeList(data: Tag.List, writer: anytype) !usize {
    var bytes_written: usize = 0;
    bytes_written += try encodeTagType(@as(TagType, data), writer);
    try writer.writeInt(i32, @intCast(data.len()), .big);
    bytes_written += 4;
    var list_iter = data.iter();
    while (list_iter.next()) |elem| {
        bytes_written += try encodeTagPayload(elem, writer);
    }
    return bytes_written;
}

fn decodeCompoundTag(reader: anytype, allocator: std.mem.Allocator, diag: Diag) !craft_io.Decoded(Tag) {
    const compound_dcd = try decodeCompound(reader, allocator, diag);
    return .{
        .value = .{ .compound = compound_dcd.value },
        .bytes_read = compound_dcd.bytes_read,
    };
}

fn decodeCompound(reader: anytype, allocator: std.mem.Allocator, diag: Diag) !craft_io.Decoded([]const NamedTag) {
    var bytes_read: usize = 0;
    var buf = std.ArrayList(NamedTag).init(allocator);
    defer buf.deinit();

    while (true) {
        const next_tag = (try decodeNamedTag(reader, allocator, diag)).unwrap(&bytes_read);
        if (next_tag.tag == .end) {
            return .{ .bytes_read = bytes_read, .value = try buf.toOwnedSlice() };
        }

        try buf.append(next_tag);
    }
}

fn encodeCompound(data: []const NamedTag, writer: anytype) !usize {
    var bytes_written: usize = 0;
    for (data) |item| {
        bytes_written += try encodeNamedTag(item, writer);
    }
    bytes_written += try encodeTagType(.end, writer);
    return bytes_written;
}

fn decodeIntArrayTag(reader: anytype, allocator: std.mem.Allocator) !craft_io.Decoded(Tag) {
    const int_array_dcd = try decodeIntArray(i32, reader, allocator);
    return .{
        .value = .{ .int_array = int_array_dcd.value },
        .bytes_read = int_array_dcd.bytes_read,
    };
}

fn decodeLongArrayTag(reader: anytype, allocator: std.mem.Allocator) !craft_io.Decoded(Tag) {
    const long_array_dcd = try decodeIntArray(i64, reader, allocator);
    return .{
        .value = .{ .long_array = long_array_dcd.value },
        .bytes_read = long_array_dcd.bytes_read,
    };
}

fn decodeIntArray(comptime Elem: type, reader: anytype, allocator: std.mem.Allocator) !craft_io.Decoded([]const Elem) {
    var bytes_read: usize = 0;
    const length: usize = @intCast(try reader.readInt(i32, .big));
    bytes_read += 4;

    const buf = try allocator.alloc(Elem, length);
    errdefer allocator.free(buf);

    for (buf) |*elem| {
        elem.* = try reader.readInt(Elem, .big);
        bytes_read += @sizeOf(Elem);
    }
    return .{ .bytes_read = bytes_read, .value = buf };
}

fn encodeIntArray(data: anytype, writer: anytype) !usize {
    const Type = @TypeOf(data);
    const Elem = @typeInfo(Type).pointer.child;

    var bytes_written: usize = 0;
    const length: i32 = @intCast(data.len);
    try writer.writeInt(i32, length, .big);
    bytes_written += 4;

    for (data) |item| {
        try writer.writeInt(Elem, item, .big);
        bytes_written += @sizeOf(Elem);
    }

    return bytes_written;
}

test "decode wiki example" {
    const example: []const u8 = &.{
        0x0a, 0x0a, 0x00, 0x0b, 0x68, 0x65, 0x6c, 0x6c,
        0x6f, 0x20, 0x77, 0x6f, 0x72, 0x6c, 0x64, 0x08,
        0x00, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x00, 0x09,
        0x42, 0x61, 0x6e, 0x61, 0x6e, 0x72, 0x61, 0x6d,
        0x61, 0x00, 0x00,
    };

    var stream = std.io.fixedBufferStream(example);
    var arena_allocator = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_allocator.deinit();
    const decoded = try craft_io.decode(
        NamedTag,
        stream.reader(),
        &arena_allocator,
        .{},
        .{},
    );

    const expected: NamedTag = .{
        .name = "",
        .tag = .{
            .compound = &.{
                .{ .name = "hello world", .tag = .{
                    .compound = &.{
                        .{ .name = "name", .tag = .{
                            .string = "Bananrama",
                        } },
                    },
                } },
            },
        },
    };

    try std.testing.expectEqualDeep(expected, decoded.value);

    var encoded = std.ArrayList(u8).init(arena_allocator.allocator());
    const bytes_encoded = try craft_io.encode(
        decoded.value,
        encoded.writer(),
        arena_allocator.allocator(),
        .{},
        .{},
    );
    try std.testing.expectEqual(encoded.items.len, bytes_encoded);
    try std.testing.expectEqualSlices(u8, example, encoded.items);
}
