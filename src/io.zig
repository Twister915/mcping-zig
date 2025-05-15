const std = @import("std");

pub const MAX_PACKET_SIZE: usize = 0x1FFFFF;

pub fn encode(
    data: anytype,
    writer: anytype,
    comptime encoding: Encoding(@TypeOf(data)),
) !usize {
    const Data = @TypeOf(data);
    if (std.meta.hasFn(Data, "craftEncode")) {
        return data.craftEncode(writer, encoding);
    }

    if (Data == u8) {
        try writer.writeByte(data);
        return 1;
    }

    if (@sizeOf(Data) == 0) {
        return 0;
    }

    return switch (@typeInfo(Data)) {
        .int => encodeInt(data, writer, encoding),
        .bool => encode(@as(u8, if (data) 1 else 0), writer, {}),
        .float => encodeFloat(data, writer),
        .pointer => encodePointer(data, writer, encoding),
        .@"struct" => encodeStruct(data, writer, encoding),
        .array => encodeArray(data, writer, encoding),
        .optional => encodeOptional(data, writer, encoding),
        .@"enum" => encodeEnum(data, writer, encoding),
        .@"union" => encodeUnion(data, writer, encoding),
        else => @compileError(@typeName(Data) ++ " cannot be craft encoded"),
    };
}

pub fn decode(
    comptime Data: type,
    reader: anytype,
    allocator: *std.heap.ArenaAllocator,
    comptime encoding: Encoding(Data),
) !Decoded(Data) {
    if (std.meta.hasFn(Data, "craftDecode")) {
        return Data.craftDecode(reader, allocator, encoding);
    }

    if (Data == u8) {
        return .{
            .value = try reader.readByte(),
            .bytes_read = 1,
        };
    }

    if (Data == void) {
        return .{ .bytes_read = 0, .value = {} };
    }

    return switch (@typeInfo(Data)) {
        .int => decodeInt(Data, reader, encoding),
        .bool => decodeBool(reader),
        .float => decodeFloat(Data, reader),
        .pointer => decodePointer(Data, reader, allocator, encoding),
        .@"struct" => decodeStruct(Data, reader, allocator, encoding),
        .array => decodeArray(Data, reader, allocator, encoding),
        .optional => decodeOptional(Data, reader, allocator, encoding),
        .@"enum" => decodeEnum(Data, reader, allocator, encoding),
        .@"union" => decodeUnion(Data, reader, allocator, encoding),
        else => @compileError(@typeName(Data) ++ " cannot be craft decoded"),
    };
}

pub fn length(data: anytype, comptime encoding: Encoding(@TypeOf(data))) !usize {
    const Data = @TypeOf(data);
    switch (@typeInfo(Data)) {
        .@"struct", .@"enum", .@"union" => {
            if (@hasDecl(Data, "CRAFT_LENGTH")) {
                return Data.CRAFT_LENGTH;
            }
        },
        else => {},
    }

    if (std.meta.hasFn(Data, "craftLength")) {
        return Data.craftLength(data, encoding);
    }

    if (Data == u8) {
        return 1;
    }

    if (@sizeOf(Data) == 0) {
        return 0;
    }

    return switch (@typeInfo(Data)) {
        .int => lengthInt(data, encoding),
        .bool, .float => @sizeOf(Data),
        .pointer => lengthPointer(data, encoding),
        .@"struct" => lengthStruct(data, encoding),
        .array => lengthArray(data, encoding),
        .optional => lengthOptional(data, encoding),
        .@"enum" => lengthEnum(data, encoding),
        .@"union" => lengthUnion(data, encoding),
        else => @compileError(@typeName(Data) ++ " is not supported by craft encoding / decoding"),
    };
}

pub const VAR_INT_BYTES: usize = 5;
pub const VAR_LONG_BYTES: usize = 10;

pub const IntEncoding = enum {
    default,
    varnum,
};

pub fn Encoding(comptime Payload: type) type {
    if (Payload == u8) {
        return void;
    }

    return switch (@typeInfo(Payload)) {
        .int => IntEncoding,
        .bool, .void, .float => void,
        .@"struct" => StructEncoding(Payload),
        .pointer => PointerEncoding(Payload),
        .@"union" => UnionEncoding(Payload),
        .@"enum" => EnumEncoding(Payload),
        .optional => |O| Encoding(O.child),
        .array => ArrayEncoding(Payload),
        else => @compileError(@typeName(Payload) ++ " cannot have encoding specified"),
    };
}

pub fn defaultEncoding(comptime Payload: type) Encoding(Payload) {
    const Enc = Encoding(Payload);
    if (Enc == void) {
        return {};
    }

    const type_info = @typeInfo(Payload);
    switch (type_info) {
        .@"struct", .@"union", .@"enum" => {
            if (@hasDecl(Payload, "ENCODING")) {
                return Payload.ENCODING;
            }
        },
        else => {},
    }

    return switch (type_info) {
        .int => IntEncoding.default,
        .@"enum" => defaultEncoding(WireTagFor(Payload)),
        .@"struct", .@"union", .pointer, .optional, .array => .{},
        else => @compileError("no default encoding computable for " ++ @typeName(Payload)),
    };
}

fn StructEncoding(comptime Struct: type) type {
    if (@hasDecl(Struct, "CraftEncoding")) {
        return Struct.CraftEncoding;
    }

    const struct_info = @typeInfo(Struct).@"struct";

    comptime var encoding_fields: [struct_info.fields.len]std.builtin.Type.StructField = undefined;
    for (struct_info.fields, &encoding_fields) |struct_field, *encoding_field| {
        const StructFieldEncoding = Encoding(struct_field.type);
        const default_value = defaultEncoding(struct_field.type);
        encoding_field.* = .{
            .name = struct_field.name,
            .type = StructFieldEncoding,
            .default_value_ptr = &default_value,
            .is_comptime = false,
            .alignment = @alignOf(StructFieldEncoding),
        };
    }

    const EncodingStruct: std.builtin.Type = .{ .@"struct" = .{
        .layout = .auto,
        .fields = &encoding_fields,
        .decls = &.{},
        .is_tuple = false,
    } };

    return @Type(EncodingStruct);
}

pub const LengthEncoding = struct {
    max: comptime_int = MAX_PACKET_SIZE,
    prefix: LengthPrefixMode = .{ .enabled = .{} },
};

pub const LengthPrefixMode = union(enum) {
    disabled,
    enabled: LengthPrefixEncoding,
};

pub const LengthPrefixEncoding = struct {
    bits: comptime_int = 32,
    encoding: IntEncoding = .varnum,

    pub fn Counter(comptime encoding: @This()) type {
        return @Type(.{ .int = .{
            .bits = encoding.bits,
            .signedness = .signed,
        } });
    }
};

pub const DEFAULT_LENGTH_ENCODING: LengthEncoding = .{};

fn PointerEncoding(comptime P: type) type {
    const pointer_info = @typeInfo(P).pointer;
    switch (pointer_info.size) {
        .one => return Encoding(pointer_info.child),
        .many, .slice => {
            // covers: []T, [*]T, [:senti]T, [*:senti]T
            if (pointer_info.size == .many and pointer_info.sentinel() == null) {
                @compileError("cannot encode " ++ @typeName(P) ++ " because has no known size (use sentinel or slice)");
            }

            const ItemsEncoding = Encoding(pointer_info.child);
            return struct {
                length: LengthEncoding = DEFAULT_LENGTH_ENCODING,
                items: ItemsEncoding = defaultEncoding(pointer_info.child),
            };
        },
        else => @compileError("unable to describe encoding for " ++ @typeName(P)),
    }
}

fn ArrayEncoding(comptime Array: type) type {
    const array_info = @typeInfo(Array).array;
    const Payload = array_info.child;
    const ItemsEncoding = Encoding(Payload);
    return struct {
        length: LengthPrefixMode = .disabled,
        items: ItemsEncoding = defaultEncoding(Payload),
    };
}

fn UnionEncoding(comptime U: type) type {
    const Tag = WireTagFor(U);

    return struct {
        tag: Encoding(Tag) = defaultEncoding(Tag),
        fields: UnionFieldsEncoding(U) = .{},
    };
}

fn UnionFieldsEncoding(comptime U: type) type {
    const union_info = @typeInfo(U).@"union";
    var encoding_fields: [union_info.fields.len]std.builtin.Type.StructField = undefined;
    for (union_info.fields, &encoding_fields) |union_field, *encoding_field| {
        const FieldEncoding = Encoding(union_field.type);
        const default_value = defaultEncoding(union_field.type);
        encoding_field.* = .{
            .name = union_field.name,
            .type = FieldEncoding,
            .default_value_ptr = &default_value,
            .is_comptime = false,
            .alignment = @alignOf(FieldEncoding),
        };
    }

    const EncodingStruct: std.builtin.Type = .{ .@"struct" = .{
        .layout = .auto,
        .fields = &encoding_fields,
        .decls = &.{},
        .is_tuple = false,
    } };

    return @Type(EncodingStruct);
}

fn EnumEncoding(comptime E: type) type {
    return Encoding(WireTagFor(E));
}

// for an int type such as u16, i16, u32, i32, etc... let's just write it as big endian on the wire
fn encodeInt(
    data: anytype,
    writer: anytype,
    comptime encoding: Encoding(@TypeOf(data)),
) !usize {
    const Int = @TypeOf(data);

    switch (encoding) {
        .default => {
            const NUM_BITS = comptime @bitSizeOf(Int);
            const BYTES = comptime std.math.divExact(usize, NUM_BITS, 8) catch @compileError(@typeName(Int) ++ " is not byte sized (divisible by 8), cannot encode");
            try writer.writeInt(Int, data, .big);
            return BYTES;
        },
        .varnum => return encodeVarnum(data, writer),
    }
}

test "encode i16 .default" {
    const TestCase = struct {
        input: i16,
        expected: [2]u8,
    };

    const test_cases: []const TestCase = &.{
        .{ .input = 1, .expected = .{ 0x00, 0x01 } },
        .{ .input = -1, .expected = .{ 0xFF, 0xFF } },
        .{ .input = 256, .expected = .{ 0x01, 0x00 } },
    };

    for (test_cases) |test_case| {
        var array_list = std.ArrayList(u8).init(std.testing.allocator);
        defer array_list.deinit();

        const bytes = try encode(test_case.input, array_list.writer(), .default);
        try std.testing.expectEqual(2, bytes);
        try std.testing.expectEqualSlices(u8, &test_case.expected, array_list.items);
    }
}

test "encode i32 .default" {
    const TestCase = struct {
        input: i32,
        expected: [4]u8,
    };

    const test_cases: []const TestCase = &.{
        .{ .input = 1, .expected = .{ 0x00, 0x00, 0x00, 0x01 } },
        .{ .input = -1, .expected = .{ 0xFF, 0xFF, 0xFF, 0xFF } },
        .{ .input = 256, .expected = .{ 0x00, 0x00, 0x01, 0x00 } },
        .{ .input = 65536, .expected = .{ 0x00, 0x01, 0x00, 0x00 } },
    };

    for (test_cases) |test_case| {
        var array_list = std.ArrayList(u8).init(std.testing.allocator);
        defer array_list.deinit();

        const bytes = try encode(test_case.input, array_list.writer(), .default);
        try std.testing.expectEqual(4, bytes);
        try std.testing.expectEqualSlices(u8, &test_case.expected, array_list.items);
    }
}

// "var num" such as VarInt, VarLong
fn encodeVarnum(data: anytype, writer: anytype) !usize {
    const IntType = @TypeOf(data);
    const UIntType = UnsignedIntEquiv(IntType);
    const MAX_BYTES = comptime std.math.divCeil(usize, @bitSizeOf(IntType), 7) catch unreachable;

    var to_encode: UIntType = @intCast(data);
    var bytes: usize = 0;
    var buf: [MAX_BYTES]u8 = undefined;
    for (&buf) |*b| {
        bytes += 1;
        b.* = @as(u8, @truncate(to_encode)) & 0x7F;
        to_encode >>= 7;
        const has_more = to_encode != 0;
        if (has_more) {
            b.* |= 0x80;
        } else {
            try writer.writeAll(buf[0..bytes]);
            return bytes;
        }
    }

    return error.VarNumTooLarge;
}

fn UnsignedIntEquiv(comptime IntType: type) type {
    const int_info = @typeInfo(IntType).int;
    return switch (int_info.signedness) {
        .unsigned => IntType,
        .signed => @Type(.{ .int = .{ .bits = int_info.bits, .signedness = .unsigned } }),
    };
}

fn encodeFloat(data: anytype, writer: anytype) !usize {
    // inspect the float passed to us... determine it's type
    const Float = @TypeOf(data);
    const NUM_BITS = @bitSizeOf(Float);

    // craft protocol defined to only work for "float" and "double" aka f32, f64
    comptime {
        switch (NUM_BITS) {
            32 => {},
            64 => {},
            else => @compileError("craft protocol only supports f32 and f64, refusing to serialize"),
        }
    }

    // compute an equiv unsigned integer type so we can do a bit cast
    // for example, f32 becomes AsInt=u32, f64 becomes AsInt=u64
    const AsInt: type = @Type(.{ .int = .{
        .bits = NUM_BITS,
        .signedness = .unsigned,
    } });

    // convert the raw bits of the float into the int type, then call encodeInt on that
    return encodeInt(@as(AsInt, @bitCast(data)), writer, .default);
}

fn encodeOptional(
    data: anytype,
    writer: anytype,
    comptime encoding: Encoding(@TypeOf(data)),
) !usize {
    return (try encode(data != null, writer, {})) +
        (if (data) |payload|
            try encode(payload, writer, encoding)
        else
            0);
}

// for a struct, let's just encode each field in the order it's declared
fn encodeStruct(
    data: anytype,
    writer: anytype,
    comptime encoding: Encoding(@TypeOf(data)),
) !usize {
    const Struct = @TypeOf(data);
    const struct_info = @typeInfo(Struct).@"struct";
    var bytes: usize = 0;
    inline for (struct_info.fields) |struct_field| {
        const field_data = @field(data, struct_field.name);
        const field_encoding = @field(encoding, struct_field.name);
        bytes += try encode(field_data, writer, field_encoding);
    }
    return bytes;
}

fn encodePointer(
    data: anytype,
    writer: anytype,
    comptime encoding: Encoding(@TypeOf(data)),
) !usize {
    const P = @TypeOf(data);
    const ptr_info = @typeInfo(P).pointer;

    switch (ptr_info.size) {
        .one => {
            switch (@typeInfo(ptr_info.child)) {
                .array => {
                    // *[N]T, can become []const T
                    const Elem: type = std.meta.Elem(ptr_info.child);
                    const ConstSlice: type = []const Elem;
                    return encode(@as(ConstSlice, data), writer, encoding);
                },
                else => {
                    // *T
                    return encode(data.*, writer, encoding);
                },
            }
        },
        .many, .slice => {
            // first, let's error out in the [*]T case, because there's no way to know when to stop encoding
            if (ptr_info.size == .many and ptr_info.sentinel() == null) {
                @compileError(@typeName(P) ++ " cannot be encoded because length cannot be determined");
            }

            // P (@TypeOf(data)) is one of these four cases:
            //
            // when Ptr.size == .slice
            // * []const T
            // * []T
            //
            // when Ptr.size == .many
            // * [*:sentinel]T
            // * [*:sentinel]const T
            //
            // We can coerce the bottom two cases into []T / []const T by using std.mem.span.
            //
            const slice = if (ptr_info.size == .many) std.mem.span(data) else data;

            var bytes: usize = 0;
            // dealing with length
            const len_encoding: LengthEncoding = encoding.length;
            switch (len_encoding.prefix) {
                .enabled => |lp| {
                    const Counter = lp.Counter();
                    const counter: Counter = @as(Counter, @intCast(slice.len));
                    bytes += try encode(counter, writer, lp.encoding);
                },
                else => {},
            }

            if (slice.len > len_encoding.max) {
                return error.PacketTooBig;
            }

            // []u8, []const u8, etc
            if (ptr_info.child == u8) {
                try writer.writeAll(slice);
                bytes += slice.len;
            } else {
                // and now with either []T or []const T, we can iterate over the items and encode
                for (slice) |item| {
                    bytes += try encode(item, writer, encoding.items);
                }
            }

            return bytes;
        },
        else => @compileError(@typeName(P) ++ " cannot be encoded because it is not supported"),
    }
}

// for a fixed size array, I guess I will just write each item independently
fn encodeArray(
    data: anytype,
    writer: anytype,
    comptime encoding: Encoding(@TypeOf(data)),
) !usize {
    const Array: type = @TypeOf(data);
    const array_info = @typeInfo(Array).array;
    var bytes: usize = 0;
    switch (encoding.length) {
        .enabled => |lp| {
            const C: type = lp.Counter();
            const counter: C = @as(C, @intCast(array_info.len));
            bytes += try encode(counter, writer, lp.encoding);
        },
        .disabled => {},
    }

    const Payload = array_info.child;
    if (Payload == u8) {
        try writer.writeAll(&data);
        bytes += array_info.len;
    } else {
        const item_encoding = encoding.items;
        inline for (0..array_info.len) |idx| {
            bytes += try encode(data[idx], writer, item_encoding);
        }
    }

    return bytes;
}

const CRAFT_TAG_FN_NAME = "craftTag";

// Given some tagged union or enum type, this will return the type of the tag we will serialize.
//
// Wire refers to "on the wire," as in "the bytes we will write on the wire to / from the craft peer."
//
// In the trivial case, the returned type is just the integer tag type associated with "Tagged."
//
// However, we support override of the tag for an enum. You can define a function called craftTag
// on your custom enum, which returns any type. This will be the data that is serialized to the
// server.
//
fn WireTagFor(comptime Tagged: type) type {
    // calculate the tag
    const type_info = @typeInfo(Tagged);
    switch (type_info) {
        // if it's an enum, then the tag_type will be the corresponding integer type
        .@"enum" => |E| {
            // check if override function is available
            if (std.meta.hasFn(Tagged, CRAFT_TAG_FN_NAME)) {
                return @typeInfo(@TypeOf(@field(Tagged, CRAFT_TAG_FN_NAME))).@"fn".return_type;
            }
            return E.tag_type;
        },
        // if it's a union, then it must have an enum tag type associated
        .@"union" => |U| {
            if (U.tag_type) |UnionTag| {
                return WireTagFor(UnionTag);
            } else {
                @compileError("untagged union " ++ @typeName(Tagged) ++ " cannot be encoded / decoded");
            }
        },
        else => @compileError("WireTagForEnum only applicable to enum / union, cannot determine tag for " ++ @tagName(Tagged)),
    }
}

// gets the actual tag value to serialize for some given enum
fn getWireTag(data: anytype) WireTagFor(@TypeOf(data)) {
    const T = @TypeOf(data);
    switch (@typeInfo(T)) {
        .@"enum" => {
            if (std.meta.hasFn(T, CRAFT_TAG_FN_NAME)) {
                return @field(data, CRAFT_TAG_FN_NAME)(data);
            } else {
                return @intFromEnum(data);
            }
        },
        else => @compileError("no associated wire tag for type " ++ @typeName(T)),
    }
}

fn encodeEnum(
    data: anytype,
    writer: anytype,
    comptime encoding: Encoding(@TypeOf(data)),
) !usize {
    return encode(getWireTag(data), writer, encoding);
}

fn encodeUnion(
    data: anytype,
    writer: anytype,
    comptime encoding: Encoding(@TypeOf(data)),
) !usize {
    switch (data) {
        inline else => |d, tag| {
            var bytes: usize = 0;
            bytes += try encode(tag, writer, encoding.tag);
            bytes += try encode(d, writer, @field(encoding.fields, @tagName(tag)));
            return bytes;
        },
    }
}

pub fn Decoded(comptime T: type) type {
    return struct {
        value: T,
        bytes_read: usize,

        pub fn unwrap(self: @This(), byte_counter: ?*usize) T {
            if (byte_counter) |ctr_ptr| {
                ctr_ptr.* += self.bytes_read;
            }

            return self.value;
        }
    };
}

pub fn decodeInt(
    comptime Int: type,
    reader: anytype,
    comptime encoding: IntEncoding,
) !Decoded(Int) {
    switch (encoding) {
        .default => {
            const NUM_BITS = @bitSizeOf(Int);
            const BYTES = comptime std.math.divExact(usize, NUM_BITS, 8) catch @compileError(@typeName(Int) ++ " is not byte sized (divisible by 8), cannot encode");

            const decoded: Int = try reader.readInt(Int, .big);
            return .{ .bytes_read = BYTES, .value = decoded };
        },
        .varnum => return decodeVarnum(Int, reader),
    }
}

fn decodeVarnum(comptime VarNum: type, reader: anytype) !Decoded(VarNum) {
    const BIT_SIZE = @bitSizeOf(VarNum);
    const MAX_BYTES = std.math.divCeil(usize, BIT_SIZE, 7) catch unreachable;
    var decoded: VarNum = 0;
    var bytes: usize = 0;
    while (true) {
        const b: u8 = try reader.readByte();
        const data: VarNum = @intCast(b & 0x7F);
        decoded |= data << @intCast(7 * bytes);
        bytes += 1;
        if ((b & 0x80) == 0) {
            return .{ .bytes_read = bytes, .value = decoded };
        } else if (bytes >= MAX_BYTES) {
            return error.VarNumTooLong;
        }
    }
}

fn decodeBool(reader: anytype) !Decoded(bool) {
    return .{
        .bytes_read = 1,
        .value = switch (try reader.readByte()) {
            0x00 => false,
            0x01 => true,
            else => return error.UnexpectedBoolByte,
        },
    };
}

fn decodeFloat(comptime Float: type, reader: anytype) !Decoded(Float) {
    const NUM_BITS = @bitSizeOf(Float);

    // craft protocol defined to only work for "float" and "double" aka f32, f64
    comptime {
        switch (NUM_BITS) {
            32, 64 => {},
            else => @compileError("craft protocol only supports f32 and f64, refusing to decode"),
        }
    }

    // compute an equiv unsigned integer type so we can do a bit cast
    // for example, f32 becomes AsInt=u32, f64 becomes AsInt=u64
    const AsInt: type = @Type(.{ .int = .{
        .bits = NUM_BITS,
        .signedness = .unsigned,
    } });

    const intDecoded: Decoded(AsInt) = try decodeInt(AsInt, reader, .default);
    const f = @as(Float, @bitCast(intDecoded));
    return .{ .bytes_read = intDecoded.bytes_read, .value = f };
}

fn decodePointer(
    comptime Data: type,
    reader: anytype,
    arena_allocator: *std.heap.ArenaAllocator,
    comptime encoding: Encoding(Data),
) !Decoded(Data) {
    const allocator = arena_allocator.allocator();
    const Ptr = @typeInfo(Data).pointer;
    const Payload = Ptr.child;
    switch (Ptr.size) {
        .one => {
            // *T
            const allocated_ptr: NonConstPointer(Data) = try allocator.create(Payload);
            errdefer allocator.destroy(allocated_ptr);

            const decoded_payload = try decode(Payload, reader, allocator, encoding);
            allocated_ptr.* = decoded_payload.value;
            return .{ .bytes_read = decoded_payload.bytes_read, .value = allocated_ptr };
        },
        .many, .slice => {
            var bytes: usize = 0;
            var dst: NonConstPointer(Data) = undefined;

            const length_encoding: LengthEncoding = encoding.length;
            switch (length_encoding.prefix) {
                .disabled => {
                    // read until reader runs dry
                    if (Payload == u8) {
                        dst = reader.readAllAlloc(allocator, length_encoding.max) catch |err| switch (err) {
                            error.StreamTooLong => return error.PacketTooBig,
                            else => return err,
                        };
                        errdefer allocator.free(dst);
                        bytes = dst.len;
                    } else {
                        @compileError(@typeName(Data) ++ " cannot be decoded without length prefix (unsupported, but TODO)");
                    }
                },
                .enabled => |lp| {
                    // decode the counter from the wire
                    const Counter = lp.Counter();
                    const count: usize = @intCast((try decodeInt(Counter, reader, lp.encoding)).unwrap(&bytes));
                    if (count > length_encoding.max) {
                        return error.PacketTooBig;
                    }

                    // use allocator to allocate a slice
                    if (Ptr.size == .many) {
                        if (Ptr.sentinel_ptr == null) {
                            @compileError("cannot decode a many pointer without a sentinel, " ++ @typeName(Data) ++ " is not supported.");
                        }

                        const sentinel_value = Ptr.sentinel();
                        dst = try allocator.allocSentinel(Payload, count, sentinel_value);
                    } else {
                        dst = try allocator.alloc(Payload, count);
                    }
                    errdefer allocator.free(dst);

                    // decode the sized data
                    if (Payload == u8) {
                        try reader.readNoEof(dst);
                        bytes += count;
                    } else {
                        for (dst) |*item| {
                            item.* = (try decode(Payload, reader, arena_allocator, encoding.items)).unwrap(&bytes);
                        }
                    }
                },
            }
            return .{
                .bytes_read = bytes,
                .value = dst,
            };
        },
        else => @compileError("cannot decode " ++ @typeName(Data)),
    }
}

fn NonConstPointer(comptime Slice: type) type {
    const ptr_info = @typeInfo(Slice).pointer;
    const T = ptr_info.child;
    switch (ptr_info.size) {
        .one => return *T,
        .many => {
            if (ptr_info.sentinel_ptr != null) {
                const sentinel: T = ptr_info.sentinel().?;
                return [*:sentinel]T;
            } else {
                @compileError(@typeName(Slice) ++ " does not have a sentinel or length, unsupported");
            }
        },
        .slice => {
            if (ptr_info.sentinel_ptr != null) {
                const sentinel: T = ptr_info.sentinel().?;
                return [:sentinel]T;
            } else {
                return []T;
            }
        },
        else => @compileError(@typeName(Slice) ++ " is not supported"),
    }
}

fn decodeStruct(
    comptime Data: type,
    reader: anytype,
    allocator: *std.heap.ArenaAllocator,
    comptime encoding: Encoding(Data),
) !Decoded(Data) {
    const S = @typeInfo(Data).@"struct";
    var decoded_value: Data = undefined;
    var bytes: usize = 0;

    inline for (S.fields) |Field| {
        const field_encoding = @field(encoding, Field.name);
        const field_dcd = try decode(Field.type, reader, allocator, field_encoding);
        @field(decoded_value, Field.name) = field_dcd.unwrap(&bytes);
    }

    return .{
        .bytes_read = bytes,
        .value = decoded_value,
    };
}

fn decodeArray(
    comptime Data: type,
    reader: anytype,
    allocator: *std.heap.ArenaAllocator,
    comptime encoding: Encoding(Data),
) !Decoded(Data) {
    const array_info = @typeInfo(Data).array;

    var bytes: usize = 0;
    switch (encoding.length) {
        .enabled => |lp| {
            const Counter: type = lp.Counter();
            const c: Counter = (try decode(
                Counter,
                reader,
                allocator,
                lp.encoding,
            )).unwrap(&bytes);

            if (@as(usize, @intCast(c)) != array_info.len) {
                return error.DecodeWrongSizedArray;
            }
        },
        .disabled => {},
    }

    const Payload = array_info.child;
    var out: Data = undefined;
    if (Payload == u8) {
        try reader.readNoEof(&out);
        bytes += array_info.len;
    } else {
        const items_encoding = encoding.items;
        inline for (&out) |*elem| {
            elem.* = (try decode(
                Payload,
                reader,
                allocator,
                items_encoding,
            )).unwrap(&bytes);
        }
    }

    return .{
        .bytes_read = bytes,
        .value = out,
    };
}

fn decodeOptional(
    comptime Data: type,
    reader: anytype,
    allocator: *std.heap.ArenaAllocator,
    comptime encoding: Encoding(Data),
) !Decoded(Data) {
    const optional_info = @typeInfo(Data).optional;

    // setup output
    var out: Decoded(Data) = .{
        .value = undefined,
        .bytes_read = 0,
    };

    // decode a bool flag (true = present, false = absent)
    const bool_flag: bool = (try decode(
        bool,
        reader,
        allocator,
        {},
    )).unwrap(&out.bytes_read);

    if (bool_flag) {
        // decode a payload item if bool flag was true
        out.value = (try decode(
            optional_info.child,
            reader,
            allocator,
            encoding,
        )).unwrap(&out.bytes_read);
    } else {
        out.value = null;
    }

    return out;
}

fn decodeEnum(
    comptime Enum: type,
    reader: anytype,
    allocator: *std.heap.ArenaAllocator,
    comptime encoding: Encoding(Enum),
) !Decoded(Enum) {
    const enum_info = @typeInfo(Enum).@"enum";

    // decode wire tag
    const WireTag: type = WireTagFor(Enum);
    const wire_tag_decoded: Decoded(WireTag) = try decode(
        WireTag,
        reader,
        allocator,
        encoding,
    );

    const wire_tag_value = wire_tag_decoded.value;

    // convert to enum
    const decoded: Enum = compute_value: {
        // if the enum has the custom craft tag function...
        if (std.meta.hasFn(Enum, CRAFT_TAG_FN_NAME)) {
            // go through all possible enum variants...
            inline for (enum_info.fields) |enum_field| {
                // calculate the craft tag for this value
                const enum_value: Enum = @enumFromInt(enum_field.value);
                const tag_value: WireTag = @field(enum_value, CRAFT_TAG_FN_NAME)();

                // if the tag matches the value decoded, then use this enum variant
                if (tag_value == wire_tag_value) {
                    break :compute_value enum_value;
                }
            }

            // after looping through all possibilities, there were no matches, so return InvalidEnumTag
            return error.InvalidEnumTag;
        } else if (WireTag == enum_info.tag_type) {
            // there is no custom craft tag function, so use the built-in tag type for this enum (an integer type)
            break :compute_value try std.meta.intToEnum(Enum, wire_tag_value);
        } else {
            // the WireTag was not the enum tag type, this is a compile error
            // should also be unreachable because of how WireTag is defined
            @compileError("cannot convert tag type " ++ @typeName(WireTag) ++ " to enum type " ++ @typeName(Enum));
        }
    };

    return .{
        .value = decoded,
        .bytes_read = wire_tag_decoded.bytes_read,
    };
}

fn decodeUnion(
    comptime Union: type,
    reader: anytype,
    allocator: *std.heap.ArenaAllocator,
    comptime encoding: Encoding(Union),
) !Decoded(Union) {
    const union_info = @typeInfo(Union).@"union";
    if (union_info.tag_type == null) {
        @compileError(@typeName(Union) ++ " is untagged and is unsupported");
    }

    const TagType: type = union_info.tag_type.?;
    const tag_info = @typeInfo(TagType).@"enum";
    var bytes: usize = 0;
    const tag_value: TagType = (try decode(TagType, reader, allocator, encoding.tag)).unwrap(&bytes);
    const tag_int: tag_info.tag_type = @intFromEnum(tag_value);
    // todo is this the best way to deal with this?
    inline for (union_info.fields, tag_info.fields) |union_field, enum_field| {
        if (enum_field.value == tag_int) {
            const Payload: type = union_field.type;
            const payload_encoding: Encoding(Payload) = @field(encoding.fields, enum_field.name);
            const payload: Payload = (try decode(Payload, reader, allocator, payload_encoding)).unwrap(&bytes);
            const out: Union = @unionInit(Union, union_field.name, payload);
            return .{
                .bytes_read = bytes,
                .value = out,
            };
        }
    }

    return error.InvalidEnumTag;
}

fn lengthInt(data: anytype, comptime encoding: IntEncoding) !usize {
    return switch (encoding) {
        .default => @sizeOf(@TypeOf(data)),
        .varnum => @max(1, try std.math.divCeil(
            usize,
            @bitSizeOf(@TypeOf(data)) - @clz(data),
            7,
        )),
    };
}

fn lengthPointer(data: anytype, comptime encoding: Encoding(@TypeOf(data))) !usize {
    const Data = @TypeOf(data);
    const ptr_info = @typeInfo(Data).pointer;
    var bytes: usize = 0;
    switch (ptr_info.size) {
        .one => {
            bytes = try length(data.*, encoding);
        },
        .many, .slice => {
            // [*]T, [*:senti]T, [:senti]T, []T
            if (ptr_info.size == .many and ptr_info.sentinel() == null) {
                @compileError("unsized non-sentinel slices are not supported");
            }

            // [*:senti]T, [:senti]T, []T
            // .many     , .slice   , .slice
            const slice = if (ptr_info.size == .many) std.mem.span(data) else data;
            // slice is always []T now
            const len_encoding: LengthEncoding = encoding.length;
            const count: usize = slice.len;
            switch (len_encoding.prefix) {
                .enabled => |lp| {
                    const Counter: type = lp.Counter();
                    const c: Counter = @intCast(count);
                    bytes += try length(c, lp.encoding);
                },
                .disabled => {},
            }

            if (ptr_info.child == u8) {
                bytes += slice.len;
            } else {
                for (slice) |item| {
                    bytes += try length(item, encoding.items);
                }
            }
        },
        else => @compileError(@typeName(Data) ++ " is not supported by Craft encode / decode"),
    }

    return bytes;
}

fn lengthStruct(data: anytype, comptime encoding: Encoding(@TypeOf(data))) !usize {
    const Data = @TypeOf(data);
    const struct_info = @typeInfo(Data).@"struct";

    var l: usize = 0;
    inline for (struct_info.fields) |field| {
        const field_data = @field(data, field.name);
        const field_encoding = @field(encoding, field.name);
        l += try length(field_data, field_encoding);
    }

    return l;
}

fn lengthArray(
    data: anytype,
    comptime encoding: Encoding(@TypeOf(data)),
) usize {
    const Array: type = @TypeOf(data);
    const array_info = @typeInfo(Array).array;
    var bytes: usize = 0;
    switch (encoding.length) {
        .enabled => |lp| {
            const C = lp.Counter();
            const count = @as(C, @intCast(array_info.len));
            bytes += try length(count, lp.encoding);
        },
        .disabled => {},
    }

    const Payload = array_info.child;
    if (Payload == u8) {
        bytes += array_info.len;
    } else {
        const items_encoding = encoding.items;
        inline for (data) |item| {
            bytes += try length(item, items_encoding);
        }
    }

    return bytes;
}

fn lengthOptional(
    data: anytype,
    comptime encoding: Encoding(@TypeOf(data)),
) !usize {
    return (if (data) |d| try length(d, encoding) else 0) + 1;
}

fn lengthEnum(data: anytype, comptime encoding: Encoding(@TypeOf(data))) !usize {
    return length(getWireTag(data), encoding);
}

fn lengthUnion(data: anytype, comptime encoding: Encoding(@TypeOf(data))) !usize {
    switch (data) {
        inline else => |body, tag| {
            const tag_bytes = try length(tag, encoding.tag);
            const field_encoding = @field(encoding.fields, @tagName(tag));
            const field_bytes = try length(body, field_encoding);
            return tag_bytes + field_bytes;
        },
    }
}
