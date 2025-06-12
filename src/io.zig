const std = @import("std");
const Diag = @import("Diag.zig");
const util = @import("util.zig");

pub const MAX_PACKET_SIZE: usize = 0x1FFFFF;
pub const MAX_IDENTIFIER_SIZE: usize = 0x7FFF;

pub fn encode(
    data: anytype,
    writer: anytype,
    allocator: std.mem.Allocator,
    diag: Diag,
    comptime encoding: Encoding(@TypeOf(data)),
) !usize {
    const Data = @TypeOf(data);
    if (std.meta.hasFn(Data, "craftEncode")) {
        return data.craftEncode(writer, allocator, diag, encoding);
    }

    const data_info = @typeInfo(Data);
    if (data_info == .int) {
        const ByteInt = std.math.ByteAlignedInt(Data);
        if (ByteInt != Data) {
            return encode(
                @as(ByteInt, @intCast(data)),
                writer,
                allocator,
                diag,
                encoding,
            );
        }
    }

    const Enc: type = Encoding(Data);
    if (Enc == JsonEncoding) {
        return encodeJson(
            data,
            writer,
            allocator,
            diag,
            encoding,
        );
    }

    if (Data == u8) {
        try writer.writeByte(data);
        return 1;
    }

    if (@sizeOf(Data) == 0) {
        return 0;
    }

    return switch (data_info) {
        .int => encodeInt(data, writer, diag, encoding, @typeName(Data)),
        .bool => encode(@as(u8, if (data) 1 else 0), writer, allocator, diag, {}),
        .float => encodeFloat(data, writer, diag),
        .pointer => encodePointer(data, writer, allocator, diag, encoding),
        .@"struct" => encodeStruct(data, writer, allocator, diag, encoding),
        .array => encodeArray(data, writer, allocator, diag, encoding),
        .optional => encodeOptional(data, writer, allocator, diag, encoding),
        .@"enum" => encodeEnum(data, writer, allocator, diag, encoding),
        .@"union" => encodeUnion(data, writer, allocator, diag, encoding),
        else => @compileError(@typeName(Data) ++ " cannot be craft encoded"),
    };
}

pub const DecodeError = error{
    PacketTooBig,
    DecodeBadData,
} || Diag.Error || std.mem.Allocator.Error;

pub fn DecodeErrorReader(comptime Reader: type) type {
    return DecodeError || Reader.NoEofError;
}

pub fn DecodeRet(comptime Data: type, comptime Reader: type) type {
    return DecodeErrorReader(Reader)!Decoded(Data);
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

pub fn decode(
    comptime Data: type,
    reader: anytype,
    allocator: *std.heap.ArenaAllocator,
    diag: Diag,
    comptime encoding: Encoding(Data),
) DecodeRet(Data, @TypeOf(reader)) {
    if (std.meta.hasFn(Data, "craftDecode")) {
        return Data.craftDecode(reader, allocator, diag, encoding);
    }

    const data_info = @typeInfo(Data);
    if (data_info == .int) {
        const ByteInt = std.math.ByteAlignedInt(Data);
        if (ByteInt != Data) {
            const decoded = try decode(ByteInt, reader, allocator, diag, encoding);
            return .{ .value = @as(Data, @intCast(decoded.value)), .bytes_read = decoded.bytes_read };
        }
    }

    const Enc: type = Encoding(Data);
    if (Enc == JsonEncoding) {
        return decodeJson(Data, reader, allocator, diag, encoding);
    }

    if (Data == u8) {
        const b: u8 = try reader.readByte();
        diag.ok(@typeName(u8), "decode", 1, "decoded byte {d}", .{b});
        return .{
            .value = b,
            .bytes_read = 1,
        };
    }

    if (Data == void) {
        return .{ .bytes_read = 0, .value = {} };
    }

    return switch (data_info) {
        .int => decodeInt(Data, reader, diag, encoding, @typeName(Data)),
        .bool => decodeBool(reader, diag),
        .float => decodeFloat(Data, reader, diag),
        .pointer => decodePointer(Data, reader, allocator, diag, encoding),
        .@"struct" => decodeStruct(Data, reader, allocator, diag, encoding),
        .array => decodeArray(Data, reader, allocator, diag, encoding),
        .optional => decodeOptional(Data, reader, allocator, diag, encoding),
        .@"enum" => decodeEnum(Data, reader, allocator, diag, encoding),
        .@"union" => decodeUnion(Data, reader, allocator, diag, encoding),
        else => @compileError(@typeName(Data) ++ " cannot be craft decoded"),
    };
}

pub fn length(
    data: anytype,
    allocator: std.mem.Allocator,
    diag: Diag,
    comptime encoding: Encoding(@TypeOf(data)),
) !usize {
    var counting_writer = std.io.countingWriter(std.io.null_writer);
    const encode_reported_bytes = try encode(data, counting_writer.writer(), allocator, diag, encoding);
    std.debug.assert(counting_writer.bytes_written == encode_reported_bytes);
    return encode_reported_bytes;
}

pub const IntEncoding = enum {
    default,
    varnum,
};

pub const JsonEncoding = struct {
    string_encoding: Encoding([]u8) = .{},
    stringify_options: std.json.StringifyOptions = .{},
    parse_options: std.json.ParseOptions = .{},
};

pub fn Encoding(comptime Payload: type) type {
    comptime {
        @setEvalBranchQuota(100000);
    }

    if (Payload == u8) {
        return void;
    }

    const payload_info = @typeInfo(Payload);

    // u6 -> u8, u14 -> u16
    if (payload_info == .int) {
        const ByteAligned = std.math.ByteAlignedInt(Payload);
        if (ByteAligned != Payload) {
            return Encoding(ByteAligned);
        }
    }

    switch (payload_info) {
        .@"struct", .@"union", .@"enum" => {
            if (@hasDecl(Payload, "CraftEncoding")) {
                return Payload.CraftEncoding;
            }
        },
        else => {},
    }

    return switch (payload_info) {
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
        .@"struct" => |struct_info| {
            if (struct_info.backing_integer) |BackingInteger| {
                comptime var int_encoding: IntEncoding = undefined;
                if (Encoding(BackingInteger) == IntEncoding) {
                    int_encoding = defaultEncoding(BackingInteger);
                } else {
                    int_encoding = .default;
                }
                return .{ .as_int = .{ .bits = @bitSizeOf(BackingInteger), .encoding = int_encoding } };
            } else {
                return .{};
            }
        },
        .optional => |opt| defaultEncoding(opt.child),
        .@"union", .pointer, .array => {
            if (@typeInfo(Enc) != .@"struct") {
                @compileError(@typeName(Payload) ++ " has encoding type " ++ @typeName(Enc) ++ " but expected to be a struct...");
            }
            return .{};
        },
        else => @compileError("no default encoding computable for " ++ @typeName(Payload)),
    };
}

fn StructEncoding(comptime Struct: type) type {
    const struct_info = @typeInfo(Struct).@"struct";
    if (struct_info.backing_integer) |BackingInt| {
        return union(enum) {
            by_fields: StructByFieldsEncoding(Struct),
            as_int: struct {
                bits: comptime_int = @typeInfo(BackingInt).int.bits,
                encoding: IntEncoding = .default,
            },
        };
    } else {
        return StructByFieldsEncoding(Struct);
    }
}

fn StructByFieldsEncoding(comptime Struct: type) type {
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
                max_items: comptime_int = MAX_PACKET_SIZE,
                length: LengthPrefixMode = .{ .enabled = .{} },
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

    comptime var defaultEncodingTag: Encoding(Tag) = undefined;
    const union_info = @typeInfo(U).@"union";
    const RealTagType = union_info.tag_type.?;
    if (@typeInfo(RealTagType) == .@"enum" and @hasDecl(RealTagType, "ENCODING")) {
        defaultEncodingTag = RealTagType.ENCODING;
    } else {
        defaultEncodingTag = defaultEncoding(Tag);
    }

    return struct {
        tag: Encoding(Tag) = defaultEncodingTag,
        fields: UnionFieldsEncoding(U) = .{},
    };
}

pub fn UnionFieldsEncoding(comptime U: type) type {
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

fn encodeInt(
    data: anytype,
    writer: anytype,
    diag: Diag,
    comptime encoding: Encoding(@TypeOf(data)),
    comptime typ: []const u8,
) !usize {
    const Int = @TypeOf(data);
    comptime if (Encoding(Int) != IntEncoding) {
        @compileError(@typeName(Int) ++ " cannot be decoded using encoding " ++ @typeName(Encoding(Int)));
    };

    switch (encoding) {
        // for an int type such as u16, i16, u32, i32, etc... let's just write it as big endian on the wire
        .default => {
            const NUM_BITS = comptime @bitSizeOf(Int);
            const BYTES = comptime std.math.divCeil(usize, NUM_BITS, 8) catch unreachable;
            writer.writeInt(Int, data, .big) catch |err| {
                diag.report(err, typ, "failed to encode as regular int", .{});
                return err;
            };
            diag.ok(typ, "encode", BYTES, "{d}", .{data});
            return BYTES;
        },
        // for a VarInt / VarLong as defined in the protocol
        .varnum => return encodeVarnum(data, writer, diag),
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

        const bytes = try encode(test_case.input, array_list.writer(), std.testing.allocator, .{}, .default);
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

        const bytes = try encode(test_case.input, array_list.writer(), std.testing.allocator, .{}, .default);
        try std.testing.expectEqual(4, bytes);
        try std.testing.expectEqualSlices(u8, &test_case.expected, array_list.items);
    }
}

// "var num" such as VarInt, VarLong
fn encodeVarnum(data: anytype, writer: anytype, diag: Diag) !usize {
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
            diag.ok(@typeName(IntType), "encode varnum", bytes, "{d}", .{data});
            return bytes;
        }
    }

    diag.report(
        error.VarNumTooLarge,
        @typeName(IntType),
        "var num exceeded max bytes {d} :: {any}",
        .{ MAX_BYTES, data },
    );
    return error.VarNumTooLarge;
}

fn UnsignedIntEquiv(comptime IntType: type) type {
    const int_info = @typeInfo(IntType).int;
    return switch (int_info.signedness) {
        .unsigned => IntType,
        .signed => @Type(.{ .int = .{ .bits = int_info.bits, .signedness = .unsigned } }),
    };
}

fn encodeFloat(data: anytype, writer: anytype, diag: Diag) !usize {
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
    return encodeInt(@as(AsInt, @bitCast(data)), writer, diag, .default, @typeName(Float));
}

fn encodeOptional(
    data: anytype,
    writer: anytype,
    allocator: std.mem.Allocator,
    diag: Diag,
    comptime encoding: Encoding(@TypeOf(data)),
) !usize {
    return (try encode(
        data != null,
        writer,
        allocator,
        try diag.child(.optional_prefix),
        {},
    )) +
        (if (data) |payload|
            try encode(
                payload,
                writer,
                allocator,
                try diag.child(.payload),
                encoding,
            )
        else
            0);
}

// for a struct, let's just encode each field in the order it's declared
fn encodeStruct(
    data: anytype,
    writer: anytype,
    allocator: std.mem.Allocator,
    diag: Diag,
    comptime encoding: Encoding(@TypeOf(data)),
) !usize {
    const Struct = @TypeOf(data);
    const struct_info = @typeInfo(Struct).@"struct";
    if (struct_info.backing_integer) |RealBackingInt| {
        switch (encoding) {
            .as_int => |int_encoding| {
                const BackingInt: type = @Type(.{ .int = .{
                    .bits = int_encoding.bits,
                    .signedness = .unsigned,
                } });
                const BackingIntEncoding: type = Encoding(BackingInt);
                comptime var encoding_for_int: BackingIntEncoding = undefined;
                comptime if (BackingIntEncoding == void) {
                    encoding_for_int = {};
                } else {
                    encoding_for_int = int_encoding.encoding;
                };
                return encode(
                    @as(BackingInt, @intCast(@as(RealBackingInt, @bitCast(data)))),
                    writer,
                    allocator,
                    diag,
                    encoding_for_int,
                );
            },
            .by_fields => |fields_encoding| return encodeStructByFields(
                data,
                writer,
                allocator,
                diag,
                fields_encoding,
            ),
        }
    } else {
        return encodeStructByFields(
            data,
            writer,
            allocator,
            diag,
            encoding,
        );
    }
}

fn encodeStructByFields(
    data: anytype,
    writer: anytype,
    allocator: std.mem.Allocator,
    diag: Diag,
    comptime encoding: anytype,
) !usize {
    const Struct = @TypeOf(data);
    const struct_info = @typeInfo(Struct).@"struct";

    var bytes: usize = 0;
    inline for (struct_info.fields) |struct_field| {
        const field_data = @field(data, struct_field.name);
        const field_encoding = if (@TypeOf(encoding) == void) @as(void, {}) else @field(encoding, struct_field.name);
        bytes += try encode(
            field_data,
            writer,
            allocator,
            try diag.child(.{ .field = struct_field.name }),
            field_encoding,
        );
    }
    return bytes;
}

// type safe variant of encodePointerInner
fn encodePointer(
    data: anytype,
    writer: anytype,
    allocator: std.mem.Allocator,
    diag: Diag,
    comptime encoding: Encoding(@TypeOf(data)),
) !usize {
    return encodePointerInner(data, writer, allocator, diag, encoding);
}

// slightly less type safe variant of encodePointer, which allows encoding to not conform to Encoding(@TypeOf(data))
fn encodePointerInner(
    data: anytype,
    writer: anytype,
    allocator: std.mem.Allocator,
    diag: Diag,
    comptime encoding: anytype,
) !usize {
    const P = @TypeOf(data);
    const ptr_info = @typeInfo(P).pointer;

    switch (ptr_info.size) {
        .one => {
            const Payload: type = ptr_info.child;
            const payload_info = @typeInfo(Payload);
            switch (payload_info) {
                .array => |array_info| {
                    // *[N]T, can become []const T
                    const ArrayPayload = array_info.child;
                    const ConstSlice: type = []const ArrayPayload;
                    return encodePointerInner(@as(ConstSlice, data), writer, allocator, diag, encoding);
                },
                else => {
                    // *T
                    return encode(data.*, writer, allocator, diag, encoding);
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
            switch (encoding.length) {
                .enabled => |lp| {
                    const Counter = lp.Counter();
                    const counter: Counter = @as(Counter, @intCast(slice.len));
                    bytes += try encode(counter, writer, allocator, try diag.child(.length_prefix), lp.encoding);
                },
                else => {},
            }

            // sometimes, an array such as *[1024]T will be converted to a slice []T. In those cases
            if (@hasField(@TypeOf(encoding), "max_items")) {
                if (slice.len > encoding.max_items) {
                    @branchHint(.unlikely);
                    diag.report(
                        error.PacketTooBig,
                        @typeName(P),
                        "items {d} exceed configured maximum {d}",
                        .{ slice.len, encoding.max_items },
                    );
                    return error.PacketTooBig;
                }
            }

            // []u8, []const u8, etc
            if (ptr_info.child == u8) {
                try writer.writeAll(slice);
                diag.ok(@typeName(P), "encode", slice.len, "{s}", .{slice});
                bytes += slice.len;
            } else {
                // and now with either []T or []const T, we can iterate over the items and encode
                for (slice, 0..) |item, idx| {
                    bytes += try encode(
                        item,
                        writer,
                        allocator,
                        try diag.child(.{ .index = idx }),
                        encoding.items,
                    );
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
    allocator: std.mem.Allocator,
    diag: Diag,
    comptime encoding: Encoding(@TypeOf(data)),
) !usize {
    const Array: type = @TypeOf(data);
    const array_info = @typeInfo(Array).array;
    var bytes: usize = 0;
    switch (encoding.length) {
        .enabled => |lp| {
            const C: type = lp.Counter();
            const counter: C = @as(C, @intCast(array_info.len));
            bytes += try encode(
                counter,
                writer,
                allocator,
                try diag.child(.length_prefix),
                lp.encoding,
            );
        },
        .disabled => {},
    }

    const Payload = array_info.child;
    if (Payload == u8) {
        try writer.writeAll(&data);
        bytes += array_info.len;
        diag.ok(@typeName(Array), "encode", array_info.len, "{s}", .{data});
    } else {
        const item_encoding = encoding.items;
        for (0..array_info.len) |idx| {
            bytes += try encode(
                data[idx],
                writer,
                allocator,
                try diag.child(.{ .index = idx }),
                item_encoding,
            );
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
    allocator: std.mem.Allocator,
    diag: Diag,
    comptime encoding: Encoding(@TypeOf(data)),
) !usize {
    return encode(getWireTag(data), writer, allocator, diag, encoding);
}

fn encodeUnion(
    data: anytype,
    writer: anytype,
    allocator: std.mem.Allocator,
    diag: Diag,
    comptime encoding: Encoding(@TypeOf(data)),
) !usize {
    const Union: type = @TypeOf(data);
    const UnionEncodingT = Encoding(Union);
    switch (data) {
        inline else => |d, tag| {
            const tag_diag = try diag.child(.{ .field = @tagName(tag) });
            var bytes: usize = 0;
            bytes += try encode(tag, writer, allocator, try tag_diag.child(.tag), encoding.tag);
            const FieldT: type = @FieldType(Union, @tagName(tag));
            const field_encoding_provided = @hasField(UnionEncodingT, "fields") and @hasField(@TypeOf(encoding.fields), @tagName(tag));
            const field_encoding = comptime if (field_encoding_provided) @field(encoding.fields, @tagName(tag)) else defaultEncoding(FieldT);
            bytes += try encode(d, writer, allocator, try tag_diag.child(.payload), field_encoding);
            return bytes;
        },
    }
}

fn encodeJson(
    data: anytype,
    writer: anytype,
    allocator: std.mem.Allocator,
    diag: Diag,
    comptime encoding: JsonEncoding,
) !usize {
    var buf = std.ArrayList(u8).init(allocator);
    defer buf.deinit();

    std.json.stringify(data, encoding.stringify_options, buf.writer()) catch |err| {
        diag.report(
            error.FailedJsonEncode,
            @typeName(@TypeOf(data)),
            "failed to encode as JSON -> {any}",
            .{err},
        );
        return error.FailedJsonEncode;
    };

    return encode(buf.items, writer, allocator, encoding.string_encoding);
}

pub fn decodeInt(
    comptime Int: type,
    reader: anytype,
    diag: Diag,
    comptime encoding: IntEncoding,
    comptime typ: []const u8,
) !Decoded(Int) {
    switch (encoding) {
        .default => {
            const NUM_BITS = @bitSizeOf(Int);
            const BYTES = comptime std.math.divCeil(usize, NUM_BITS, 8) catch unreachable;

            const decoded: Int = reader.readInt(Int, .big) catch |err| {
                diag.report(err, typ, "failed to decode int", .{});
                return err;
            };
            diag.ok(typ, "decode", BYTES, "{d}", .{decoded});
            return .{ .bytes_read = BYTES, .value = decoded };
        },
        .varnum => return decodeVarnum(Int, reader, diag),
    }
}

fn decodeVarnum(comptime VarNum: type, reader: anytype, diag: Diag) !Decoded(VarNum) {
    const BIT_SIZE = @bitSizeOf(VarNum);
    const MAX_BYTES = comptime std.math.divCeil(usize, BIT_SIZE, 7) catch unreachable;
    var decoded: VarNum = 0;
    var bytes: usize = 0;
    while (true) {
        const b: u8 = reader.readByte() catch |err| {
            diag.report(err, @typeName(VarNum), "failed to decode byte for varnum", .{});
            return err;
        };

        const data: VarNum = @intCast(b & 0x7F);
        decoded |= data << @intCast(7 * bytes);
        bytes += 1;
        if ((b & 0x80) == 0) {
            diag.ok(@typeName(VarNum), "decode varnum", bytes, "{d}", .{decoded});
            return .{ .bytes_read = bytes, .value = decoded };
        } else if (bytes >= MAX_BYTES) {
            @branchHint(.unlikely);
            diag.report(error.VarNumTooLarge, @typeName(VarNum), "too many bytes while decoding var num", .{});
            return error.DecodeBadData;
        }
    }
}

fn decodeBool(reader: anytype, diag: Diag) !Decoded(bool) {
    const byte = reader.readByte() catch |err| {
        diag.report(err, "bool", "failed to read byte for a bool", .{});
        return err;
    };

    const out: Decoded(bool) = .{
        .bytes_read = 1,
        .value = switch (byte) {
            0x00 => false,
            0x01 => true,
            else => |other| {
                @branchHint(.unlikely);
                diag.report(error.UnexpectedBoolByte, "bool", "bad bool value 0x{X:0>2}", .{other});
                return error.DecodeBadData;
            },
        },
    };
    diag.ok(@typeName(bool), "decode", 1, "{any}", .{out.value});
    return out;
}

fn decodeFloat(comptime Float: type, reader: anytype, diag: Diag) !Decoded(Float) {
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

    const int_decoded: Decoded(AsInt) = try decodeInt(AsInt, reader, diag, .default, @typeName(Float));
    const f = @as(Float, @bitCast(int_decoded.value));
    return .{ .bytes_read = int_decoded.bytes_read, .value = f };
}

fn decodePointer(
    comptime Data: type,
    reader: anytype,
    arena_allocator: *std.heap.ArenaAllocator,
    diag: Diag,
    comptime encoding: Encoding(Data),
) DecodeErrorReader(@TypeOf(reader))!Decoded(Data) {
    const allocator = arena_allocator.allocator();
    const Ptr = @typeInfo(Data).pointer;
    const Payload = Ptr.child;
    switch (Ptr.size) {
        .one => {
            const payload_info = @typeInfo(Payload);
            switch (payload_info) {
                .array => |array_info| {
                    // this handles case *[N]Elem or *const [N]Elem
                    const Elem = array_info.child;
                    const N = array_info.len;
                    var bytes_read: usize = 0;
                    switch (encoding.length) {
                        .enabled => |lp| {
                            const Cnt = lp.Counter();
                            const count_dcd: usize = @intCast(
                                (try decode(
                                    Cnt,
                                    reader,
                                    allocator,
                                    try diag.child(.length_prefix),
                                    lp.encoding,
                                )).unwrap(&bytes_read),
                            );
                            if (count_dcd != N) {
                                @branchHint(.unlikely);
                                diag.report(
                                    error.ExactSizedArrayBadLengthPrefix,
                                    @typeName(Data),
                                    "decoded length prefix {d} but expected exact size {d}",
                                    .{ count_dcd, N },
                                );
                                return error.DecodeBadData;
                            }
                        },
                        .disabled => {},
                    }

                    // allocate [N]Elem on the heap
                    const buf: []Elem = try allocator.alloc(Elem, N);
                    errdefer allocator.free(buf);

                    // if Elem is u8, then decode bytes directly
                    if (Elem == u8) {
                        try reader.readNoEof(buf);
                        diag.ok(@typeName(Data), "decode", N, "{s}", .{buf});
                        bytes_read += N;
                    } else {
                        // otherwise, decode each item individually
                        const items_encoding = encoding.items;
                        for (buf, 0..) |*target, idx| {
                            target.* = (try decode(
                                Elem,
                                reader,
                                allocator,
                                try diag.child(.{ .index = idx }),
                                items_encoding,
                            )).unwrap(&bytes_read);
                        }
                    }

                    return .{
                        .value = @ptrCast(buf),
                        .bytes_read = bytes_read,
                    };
                },
                else => {
                    // other *T, not arrays
                    const allocated_ptr: NonConstPointer(Data) = try allocator.create(Payload);
                    errdefer allocator.destroy(allocated_ptr);

                    const decoded_payload = try decode(Payload, reader, arena_allocator, diag, encoding);
                    allocated_ptr.* = decoded_payload.value;
                    return .{ .bytes_read = decoded_payload.bytes_read, .value = allocated_ptr };
                },
            }
        },
        .many, .slice => {
            var bytes: usize = 0;
            var dst: NonConstPointer(Data) = undefined;

            switch (encoding.length) {
                .disabled => {
                    // read until reader runs dry
                    if (Payload == u8) {
                        dst = reader.readAllAlloc(allocator, encoding.max_items) catch |err| switch (err) {
                            error.StreamTooLong => return error.PacketTooBig,
                            inline else => |e| return e,
                        };
                        errdefer allocator.free(dst);
                        bytes = dst.len;
                        if (util.shouldDiagPrintBytes(dst)) {
                            diag.ok(
                                @typeName(Data),
                                "decode",
                                dst.len,
                                "{s}",
                                .{dst},
                            );
                        } else {
                            diag.ok(@typeName(Data), "decode", dst.len, "[{d} bytes]", .{bytes});
                        }
                    } else {
                        @compileError(@typeName(Data) ++ " cannot be decoded without length prefix (unsupported, but TODO)");
                    }
                },
                .enabled => |lp| {
                    // decode the counter from the wire
                    const Counter = lp.Counter();
                    const count: usize = @intCast((try decodeInt(
                        Counter,
                        reader,
                        try diag.child(.length_prefix),
                        lp.encoding,
                        @typeName(Counter),
                    )).unwrap(&bytes));
                    if (count > encoding.max_items) {
                        @branchHint(.unlikely);
                        diag.report(
                            error.PacketTooBig,
                            @typeName(Data),
                            "decoded length prefix {d} larger than max_items {d}",
                            .{ count, encoding.max_items },
                        );
                        return error.PacketTooBig;
                    }

                    // use allocator to allocate a slice
                    if (Ptr.size == .many) {
                        comptime if (Ptr.sentinel_ptr == null) {
                            @compileError("cannot decode a many pointer without a sentinel, " ++ @typeName(Data) ++ " is not supported.");
                        };

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
                        if (util.shouldDiagPrintBytes(dst)) {
                            diag.ok(
                                @typeName(Data),
                                "decode",
                                count,
                                "{s}",
                                .{dst},
                            );
                        } else {
                            diag.ok(
                                @typeName(Data),
                                "decode",
                                count,
                                "[{d} bytes]",
                                .{count},
                            );
                        }
                    } else {
                        for (dst, 0..) |*item, idx| {
                            item.* = (try decode(
                                Payload,
                                reader,
                                arena_allocator,
                                try diag.child(.{ .index = idx }),
                                encoding.items,
                            )).unwrap(&bytes);
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
    diag: Diag,
    comptime encoding: Encoding(Data),
) !Decoded(Data) {
    const struct_info = @typeInfo(Data).@"struct";
    if (struct_info.backing_integer) |RealBackingInt| {
        switch (encoding) {
            .as_int => |int_encoding| {
                const BackingInt: type = @Type(.{ .int = .{ .bits = int_encoding.bits, .signedness = .unsigned } });
                const BackingIntEncoding: type = Encoding(BackingInt);
                comptime var encoding_for_int: BackingIntEncoding = undefined;
                comptime if (BackingIntEncoding == void) {
                    encoding_for_int = {};
                } else {
                    encoding_for_int = int_encoding.encoding;
                };
                const int_repr = try decode(
                    BackingInt,
                    reader,
                    allocator,
                    diag,
                    encoding_for_int,
                );
                const as_struct: Data = @bitCast(@as(RealBackingInt, @truncate(int_repr.value)));
                return .{
                    .bytes_read = int_repr.bytes_read,
                    .value = as_struct,
                };
            },
            .by_fields => |fields_encoding| {
                return decodeStructByFields(Data, reader, allocator, diag, fields_encoding);
            },
        }
    } else {
        return decodeStructByFields(Data, reader, allocator, diag, encoding);
    }
}

fn decodeStructByFields(
    comptime Data: type,
    reader: anytype,
    allocator: *std.heap.ArenaAllocator,
    diag: Diag,
    comptime encoding: Encoding(Data),
) !Decoded(Data) {
    const struct_info = @typeInfo(Data).@"struct";
    var decoded_value: Data = undefined;
    var bytes: usize = 0;

    inline for (struct_info.fields) |struct_field| {
        const field_encoding = comptime if (@hasField(Encoding(Data), struct_field.name)) @field(encoding, struct_field.name) else defaultEncoding(struct_field.type);
        const field_dcd = try decode(
            struct_field.type,
            reader,
            allocator,
            try diag.child(.{ .field = struct_field.name }),
            field_encoding,
        );
        @field(decoded_value, struct_field.name) = field_dcd.unwrap(&bytes);
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
    diag: Diag,
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
                try diag.child(.length_prefix),
                lp.encoding,
            )).unwrap(&bytes);

            if (@as(usize, @intCast(c)) != array_info.len) {
                @branchHint(.cold);
                diag.report(
                    error.DecodeWrongSizedArray,
                    @typeName(Data),
                    "expected exact size {d} but decoded length prefix size {d}",
                    .{ array_info.len, c },
                );
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
        diag.ok(@typeName(Data), "decodeArray", array_info.len, "decoded bytes: {any}", .{out});
    } else {
        const items_encoding = encoding.items;
        for (&out, 0..) |*elem, idx| {
            elem.* = (try decode(
                Payload,
                reader,
                allocator,
                try diag.child(.{ .index = idx }),
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
    diag: Diag,
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
        try diag.child(.optional_prefix),
        {},
    )).unwrap(&out.bytes_read);

    if (bool_flag) {
        // decode a payload item if bool flag was true
        out.value = (try decode(
            optional_info.child,
            reader,
            allocator,
            try diag.child(.payload),
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
    diag: Diag,
    comptime encoding: Encoding(Enum),
) !Decoded(Enum) {
    const enum_info = @typeInfo(Enum).@"enum";

    // decode wire tag
    const WireTag: type = WireTagFor(Enum);
    const wire_tag_decoded: Decoded(WireTag) = try decode(
        WireTag,
        reader,
        allocator,
        diag,
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
            diag.report(
                error.InvalidEnumTag,
                @typeName(Enum),
                "decoded an invalid enum tag, got the value {d}",
                .{wire_tag_value},
            );
            return error.DecodeBadData;
        } else if (WireTag == enum_info.tag_type) {
            // there is no custom craft tag function, so use the built-in tag type for this enum (an integer type)
            break :compute_value std.meta.intToEnum(Enum, wire_tag_value) catch |err| {
                if (err == error.InvalidEnumTag) {
                    diag.report(
                        error.InvalidEnumTag,
                        @typeName(Enum),
                        "decoded an invalid enum tag, got the value {d}",
                        .{wire_tag_value},
                    );
                }
                return error.DecodeBadData;
            };
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
    diag: Diag,
    comptime encoding: Encoding(Union),
) !Decoded(Union) {
    const UnionEncodingT = @TypeOf(encoding);
    const union_info = @typeInfo(Union).@"union";
    if (union_info.tag_type == null) {
        @compileError(@typeName(Union) ++ " is untagged and is unsupported");
    }

    const TagType: type = union_info.tag_type.?;
    var bytes: usize = 0;
    const tag_value: TagType = (try decode(
        TagType,
        reader,
        allocator,
        try diag.child(.tag),
        encoding.tag,
    )).unwrap(&bytes);
    switch (tag_value) {
        inline else => |tag_value_comptime| {
            const tag_name = @tagName(tag_value_comptime);
            const Payload: type = @FieldType(Union, tag_name);
            const field_encoding_provided = @hasField(UnionEncodingT, "fields") and @hasField(@TypeOf(encoding.fields), tag_name);
            const payload_encoding = comptime if (field_encoding_provided) @field(encoding.fields, tag_name) else defaultEncoding(Payload);
            const payload: Payload = (try decode(
                Payload,
                reader,
                allocator,
                try diag.child(.{ .field = tag_name }),
                payload_encoding,
            )).unwrap(&bytes);
            const out: Union = @unionInit(Union, tag_name, payload);
            return .{
                .bytes_read = bytes,
                .value = out,
            };
        },
    }

    return error.DecodeBadData;
}

fn decodeJson(
    comptime Data: type,
    reader: anytype,
    arena_allocator: *std.heap.ArenaAllocator,
    diag: Diag,
    comptime encoding: JsonEncoding,
) !Decoded(Data) {
    const str_decode = try decode([]u8, reader, arena_allocator, diag, encoding.string_encoding);
    const allocator = arena_allocator.allocator();
    // we don't deallocate str_decode because json parser might point to the memory allocated for the string

    // we use leaky here because we are guranteed to be using an arena allocator
    const parsed: Data = std.json.parseFromSliceLeaky(Data, allocator, str_decode.value, encoding.parse_options) catch |err| {
        diag.report(
            error.FailedJsonDecode,
            @typeName(Data),
            "failed to JSON decode ({any}) from string: {s}",
            .{ err, str_decode.value },
        );
        return error.DecodeBadData;
    };
    return .{
        .value = parsed,
        .bytes_read = str_decode.bytes_read,
    };
}

pub const MAX_VAR_INT_LENGTH = maxIntLength(i32, .varnum);

pub fn maxIntLength(comptime Int: type, comptime encoding: IntEncoding) usize {
    return switch (encoding) {
        .default => @sizeOf(Int),
        .varnum => std.math.divCeil(usize, @bitSizeOf(Int), 7) catch unreachable,
    };
}

test "encoding numeric tagged union" {
    const UUID = @import("UUID.zig");

    const PlayerTarget = struct {
        player_name: []const u8,
        player_id: UUID,

        pub const ENCODING: Encoding(@This()) = .{
            .player_name = .{ .max_items = 12 },
        };
    };

    const ScoreboardActionTag = enum(i32) { add, remove, clear };

    const ScoreboardAction = union(ScoreboardActionTag) {
        add: PlayerTarget,
        remove: PlayerTarget,
        clear,

        pub const ENCODING: Encoding(@This()) = .{ .tag = .varnum };
    };

    const ScoreboardPacket = struct {
        actions: []const ScoreboardAction,
    };

    const sb_pkt: ScoreboardPacket = .{ .actions = &.{
        .{ .remove = .{
            .player_name = "joey",
            .player_id = UUID.random(std.crypto.random),
        } },
        .{ .add = .{
            .player_name = "bill",
            .player_id = UUID.random(std.crypto.random),
        } },
        .{ .add = .{
            .player_name = "albert",
            .player_id = UUID.random(std.crypto.random),
        } },
        .{ .remove = .{
            .player_name = "the devil",
            .player_id = UUID.random(std.crypto.random),
        } },
    } };

    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const allocator = arena.allocator();

    var buf = std.ArrayList(u8).init(allocator);
    var diag_state = Diag.State.init(&arena);

    const sb_pkt_encoding: Encoding(ScoreboardPacket) = .{};
    _ = encode(
        sb_pkt,
        buf.writer(),
        allocator,
        diag_state.diag(),
        .{},
    ) catch |err| {
        std.debug.print(
            "failed to encode... diag items {any}\n",
            .{diag_state.reports.items},
        );
        return err;
    };
    std.debug.print(
        "\nin: {any}\nencoding: {any}\nout:{any}\n",
        .{ sb_pkt, sb_pkt_encoding, buf.items },
    );
    std.debug.print("diag items: {any}\n", .{diag_state.reports.items});

    var stream = std.io.fixedBufferStream(buf.items);
    const sb_pkt_decoded = (try decode(
        ScoreboardPacket,
        stream.reader(),
        &arena,
        diag_state.diag(),
        sb_pkt_encoding,
    )).unwrap(null);
    std.debug.print("\ndecoded: {any}\n", .{sb_pkt_decoded});

    try std.testing.expectEqual(
        buf.items.len,
        try length(
            sb_pkt,
            arena.allocator(),
            .{},
            sb_pkt_encoding,
        ),
    );
}

test "encode heap arrays u8" {
    const TestPacket = struct {
        fixed_data1: *const [128]u8,
        fixed_data2: *const [256]u8,
    };

    const d1: [128]u8 = .{18} ** 128;
    const d2: [256]u8 = .{7} ** 256;

    const test_pkt: TestPacket = .{
        .fixed_data1 = &d1,
        .fixed_data2 = &d2,
    };

    var encode_buf = std.ArrayList(u8).init(std.testing.allocator);
    defer encode_buf.deinit();

    _ = try encode(test_pkt, encode_buf.writer(), std.testing.allocator, .{}, .{});

    var decode_stream = std.io.fixedBufferStream(encode_buf.items);
    var decode_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer decode_arena.deinit();
    const test_pkt_decoded: TestPacket = (try decode(
        TestPacket,
        decode_stream.reader(),
        &decode_arena,
        .{},
        .{},
    )).unwrap(null);
    try std.testing.expectEqualDeep(test_pkt, test_pkt_decoded);
}

pub const Position = packed struct {
    y: i12,
    z: i26,
    x: i26,
};

pub fn IdOr(comptime Payload: type) type {
    return union(enum) {
        id: i32,
        other: Payload,

        const Self = @This();

        pub const CraftEncoding: type = Encoding(Payload);

        pub fn craftEncode(
            id_or: Self,
            writer: anytype,
            allocator: std.mem.Allocator,
            diag: Diag,
            comptime encoding: CraftEncoding,
        ) !usize {
            switch (id_or) {
                .id => |id_value| {
                    return encode(
                        id_value + 1,
                        writer,
                        allocator,
                        diag,
                        .varnum,
                    );
                },
                .other => |payload| {
                    var bytes_written: usize = 0;
                    bytes_written += try encode(
                        @as(i32, 0),
                        writer,
                        allocator,
                        try diag.child(.{ .field = "id" }),
                        .varnum,
                    );
                    bytes_written += try encode(
                        payload,
                        writer,
                        allocator,
                        try diag.child(.{ .field = "value" }),
                        encoding,
                    );
                    return bytes_written;
                },
            }
        }

        pub fn craftDecode(
            reader: anytype,
            arena_allocator: *std.heap.ArenaAllocator,
            diag: Diag,
            comptime encoding: CraftEncoding,
        ) !Decoded(Self) {
            var bytes_read: usize = 0;
            const id_value: i32 = (try decode(
                i32,
                reader,
                arena_allocator,
                try diag.child(.{ .field = "id" }),
                .varnum,
            )).unwrap(&bytes_read);

            var out: Self = undefined;
            if (id_value == 0) {
                out = .{ .other = (try decode(
                    Payload,
                    reader,
                    arena_allocator,
                    try diag.child(.{ .field = "value" }),
                    encoding,
                )).unwrap(&bytes_read) };
            } else {
                out = .{ .id = id_value - 1 };
            }
            return .{
                .bytes_read = bytes_read,
                .value = out,
            };
        }

        pub fn format(
            data: Self,
            comptime fmt: []const u8,
            options: std.fmt.FormatOptions,
            writer: anytype,
        ) !void {
            _ = fmt;
            _ = options;

            switch (data) {
                .id => |id| try std.fmt.format(writer, "IdOr(id = {d})", .{id}),
                .other => |payload| try std.fmt.format(writer, "IdOr(payload = {any})", .{payload}),
            }
        }
    };
}
