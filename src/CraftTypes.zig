const std = @import("std");

pub const MAX_PACKET_SIZE: usize = 0x80000000;

pub fn encode(data: anytype, writer: anytype) !usize {
    const Data = @TypeOf(data);
    if (std.meta.hasFn(Data, "craftEncode")) {
        return data.craftEncode(writer);
    }

    if (Data == u8) {
        try writer.writeByte(data);
        return 1;
    }

    if (@sizeOf(Data) == 0) {
        return 0;
    }

    return switch (@typeInfo(Data)) {
        .int => encodeInt(data, writer),
        .bool => encode(@as(u8, if (data) 1 else 0), writer),
        .float => encodeFloat(data, writer),
        .pointer => |Ptr| encodePointer(Ptr, data, writer),
        .@"struct" => |S| encodeStruct(S, data, writer),
        .array => |A| encodeArray(A, data, writer),
        .optional => encodeOptional(data, writer),
        .@"enum" => |E| encodeEnum(E, data, writer),
        else => @compileError(@typeName(Data) ++ " cannot be craft encoded"),
    };
}

pub fn decode(comptime Data: type, reader: anytype, allocator: std.mem.Allocator) !Decoded(Data) {
    if (std.meta.hasFn(Data, "craftDecode")) {
        return Data.craftDecode(reader, allocator);
    }

    if (Data == u8) {
        return .{
            .value = try reader.readByte(),
            .bytes_read = 1,
        };
    }

    if (@sizeOf(Data) == 0) {
        return 0;
    }

    return switch (@typeInfo(Data)) {
        .int => decodeInt(Data, reader),
        .bool => decodeBool(reader),
        .float => decodeFloat(Data, reader),
        .pointer => |Ptr| decodePointer(Ptr, Data, reader, allocator),
        .@"struct" => |S| decodeStruct(S, Data, reader, allocator),
        .array => |A| decodeArray(A, Data, reader, allocator),
        .optional => |Opt| decodeOptional(Opt, Data, reader, allocator),
        .@"enum" => |E| decodeEnum(E, Data, reader, allocator),
        else => @compileError(@typeName(Data) ++ " cannot be craft decoded"),
    };
}

pub const VarInt = enum(i32) {
    _,

    pub usingnamespace AutoVarNum(@This());
};
pub const VarLong = enum(i64) {
    _,

    pub usingnamespace AutoVarNum(@This());
};

fn AutoVarNum(comptime Wrapper: type) type {
    return struct {
        pub const Int = @typeInfo(Wrapper).@"enum".tag_type;
        pub const BIT_SIZE = @typeInfo(Int).int.bits;
        pub const BYTE_SIZE = std.math.divCeil(usize, BIT_SIZE, 7) catch unreachable;

        pub fn craftEncode(data: Wrapper, writer: anytype) !usize {
            return encodeVarnum(@intFromEnum(data), writer);
        }

        pub fn craftDecode(reader: anytype, _: std.mem.Allocator) !Decoded(Wrapper) {
            return decodeVarnum(Wrapper, reader);
        }

        pub fn length(value: Wrapper) usize {
            return @max(
                1,
                std.math.divCeil(
                    usize,
                    @as(usize, @intCast(BIT_SIZE)) - @clz(@intFromEnum(value)),
                    7,
                ) catch unreachable,
            );
        }
    };
}

// "var num" such as VarInt, VarLong
fn encodeVarnum(data: anytype, writer: anytype) !usize {
    const VarNumType = comptime @TypeOf(data);
    const NUM_BITS = comptime @bitSizeOf(VarNumType);
    const MAX_BYTES = comptime std.math.divCeil(usize, NUM_BITS, 7) catch unreachable;

    var to_encode = data;
    var bytes: usize = 0;
    while (true) {
        var b: u8 = @intCast(to_encode & 0x7F);
        to_encode >>= 7;
        const has_more = to_encode != 0;
        if (has_more) {
            b |= 0x80;
        }
        bytes += try encode(b, writer);
        if (!has_more) {
            return bytes;
        } else if (bytes >= MAX_BYTES) {
            return error.VarNumTooLarge;
        }
    }
}

// for an int type such as u16, i16, u32, i32, etc... let's just write it as big endian on the wire
fn encodeInt(data: anytype, writer: anytype) !usize {
    // all of this is calculated at comptime
    const Int = comptime @TypeOf(data);
    const NUM_BITS = comptime @bitSizeOf(Int);
    const BYTES = comptime std.math.divExact(usize, NUM_BITS, 8) catch @compileError(@typeName(Int) ++ " is not byte sized (divisible by 8), cannot encode");

    try writer.writeInt(Int, data, .big);

    return BYTES;
}

fn encodeFloat(data: anytype, writer: anytype) !usize {
    // inspect the float passed to us... determine it's type
    const Float = comptime @TypeOf(data);
    const NUM_BITS = comptime @bitSizeOf(Float);

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
    const AsInt: type = comptime @Type(.{ .int = .{
        .bits = NUM_BITS,
        .signedness = .unsigned,
    } });

    // convert the raw bits of the float into the int type, then call encodeInt on that
    return encodeInt(@as(AsInt, @bitCast(data)), writer);
}

fn encodeOptional(data: anytype, writer: anytype) !usize {
    if (data) |payload| {
        return try encode(true, writer) + try encode(payload, writer);
    } else {
        return try encode(false, writer);
    }
}

// for a struct, let's just encode each field in the order it's declared
fn encodeStruct(comptime S: std.builtin.Type.Struct, data: anytype, writer: anytype) !usize {
    var bytes: usize = 0;
    inline for (S.fields) |Field| {
        bytes += try encode(@field(data, Field.name), writer);
    }
    return bytes;
}

fn encodePointer(comptime Ptr: std.builtin.Type.Pointer, data: anytype, writer: anytype) !usize {
    const P = comptime @TypeOf(data);

    switch (Ptr.size) {
        .one => {
            switch (@typeInfo(Ptr.child)) {
                .array => {
                    // *[N]T, can become []const T
                    const Elem: type = std.meta.Elem(Ptr.child);
                    const ConstSlice: type = []const Elem;
                    return encode(@as(ConstSlice, data));
                },
                else => {
                    // *T
                    return encode(data.*, writer);
                },
            }
        },
        .many, .slice => {
            // first, let's error out in the [*]T case, because there's no way to know when to stop encoding
            if (Ptr.size == .many and Ptr.sentinel() == null) {
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
            const slice = if (Ptr.size == .many) std.mem.span(data) else data;

            // []u8, []const u8, etc
            if (Ptr.child == u8) {
                try writer.writeAll(slice);
                return slice.len;
            } else {
                // and now with either []T or []const T, we can iterate over the items and encode
                var bytes: usize = 0;
                for (slice) |item| {
                    bytes += try encode(item, writer);
                }
                return bytes;
            }
        },
        else => @compileError(@typeName(P) ++ " cannot be encoded because it is not supported"),
    }
}

// for a fixed size array, I guess I will just write each item independently
fn encodeArray(comptime A: std.builtin.Type.Array, data: anytype, writer: anytype) !usize {
    var bytes: usize = 0;
    inline for (0..A.len) |idx| {
        bytes += try encode(data[idx], writer);
    }
    return bytes;
}

fn encodeEnum(comptime E: std.builtin.Type.Enum, data: anytype, writer: anytype) !usize {
    const Enum = comptime @TypeOf(data);
    const Tag = comptime E.tag_type;

    const encode_tag_fn_name = "craftEncodeTag";
    if (std.meta.hasFn(Enum, encode_tag_fn_name)) {
        const fn_handle = @field(Enum, encode_tag_fn_name);
        const fn_info = @typeInfo(@TypeOf(fn_handle)).@"fn";
        // fn could accept the enum type itself, or it could accept the tag type
        if (fn_info.params.len != 1) {
            @compileError(@typeName(Enum) ++ "." ++ encode_tag_fn_name ++ " must declare exactly one parameter");
        }

        const param0_type = fn_info.params[0].type.?;
        switch (param0_type) {
            Enum => return encode(@call(.auto, fn_handle, .{data}), writer),
            Tag => return encode(@call(.auto, fn_handle, .{@intFromEnum(data)}), writer),
            else => @compileError("cannot use " ++ @typeName(Enum) ++ "." ++ encode_tag_fn_name ++ "(" ++ @typeName(param0_type) ++ ") because parameter type is not supported"),
        }
    } else {
        return encode(@intFromEnum(data), writer);
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

fn decodeVarnum(comptime VarNum: type, reader: anytype) !Decoded(VarNum) {
    const BIT_SIZE = comptime @bitSizeOf(VarNum);
    const MAX_BYTES = comptime std.math.divCeil(usize, BIT_SIZE, 7) catch unreachable;
    comptime {
        switch (@typeInfo(VarNum)) {
            .@"enum" => {},
            else => @compileError("var num must be enum with integer tag"),
        }
    }

    const Int = comptime @typeInfo(VarNum).@"enum".tag_type;
    comptime {
        switch (@typeInfo(Int)) {
            .int => {},
            else => @compileError("var num must be enum with integer tag"),
        }
    }

    var decoded: Int = 0;
    var bytes: usize = 0;
    while (true) {
        const b: u8 = try reader.readByte();
        const data: Int = @intCast(b & 0x7F);
        decoded |= data << @intCast(7 * bytes);
        bytes += 1;
        if ((b & 0x80) == 0) {
            return .{ .bytes_read = bytes, .value = @enumFromInt(decoded) };
        } else if (bytes >= MAX_BYTES) {
            return error.VarNumTooLong;
        }
    }
}

fn decodeInt(comptime Int: type, reader: anytype) !Decoded(Int) {
    const NUM_BITS = comptime @bitSizeOf(Int);
    const BYTES = comptime std.math.divExact(usize, NUM_BITS, 8) catch @compileError(@typeName(Int) ++ " is not byte sized (divisible by 8), cannot encode");

    const decoded: Int = try reader.readInt(Int, .big);
    return .{ .bytes_read = BYTES, .value = decoded };
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
    const NUM_BITS = comptime @bitSizeOf(Float);

    // craft protocol defined to only work for "float" and "double" aka f32, f64
    comptime {
        switch (NUM_BITS) {
            32 => {},
            64 => {},
            else => @compileError("craft protocol only supports f32 and f64, refusing to decode"),
        }
    }

    // compute an equiv unsigned integer type so we can do a bit cast
    // for example, f32 becomes AsInt=u32, f64 becomes AsInt=u64
    const AsInt: type = comptime @Type(.{ .int = .{
        .bits = NUM_BITS,
        .signedness = .unsigned,
    } });

    const intDecoded: Decoded(AsInt) = try decodeInt(AsInt, reader);
    const f = @as(Float, @bitCast(intDecoded));
    return .{ .bytes_read = intDecoded.bytes_read, .value = f };
}

fn decodePointer(comptime _: std.builtin.Type.Pointer, comptime Data: type, _: anytype, _: std.mem.Allocator) !Decoded(Data) {
    @compileError("cannot decode " ++ @typeName(Data));
    // fn decodePointer(comptime Ptr: std.builtin.Type.Pointer, comptime Data: type, reader: anytype, allocator: std.mem.Allocator) !Decoded(Data) {
    // const P = @TypeOf(Data);
    // switch (Ptr.size) {
    //     .one => {},
    // }
}

fn decodeStruct(comptime S: std.builtin.Type.Struct, comptime Data: type, reader: anytype, allocator: std.mem.Allocator) !Decoded(Data) {
    var decoded_value: Data = undefined;
    var bytes: usize = 0;

    inline for (S.fields) |Field| {
        @field(decoded_value, Field.name) = (try decode(Field.type, reader, allocator)).unwrap(&bytes);
    }

    return .{
        .bytes_read = bytes,
        .value = decoded_value,
    };
}

// fn decodeArray(comptime A: std.builtin.Type.Array, comptime Data: type, reader: anytype, allocator: std.mem.Allocator) !Decoded(Data) {
fn decodeArray(comptime _: std.builtin.Type.Array, comptime Data: type, _: anytype, _: std.mem.Allocator) !Decoded(Data) {
    @compileError("cannot decode " ++ @typeName(Data));
}

fn decodeOptional(comptime Opt: std.builtin.Type.Optional, comptime Data: type, reader: anytype, allocator: std.mem.Allocator) !Decoded(Data) {
    var out: Decoded(Data) = undefined;
    out.bytes_read = 0;

    const has_payload: bool = (try decode(bool, reader, allocator)).unwrap(&out.bytes_read);

    if (has_payload) {
        out.value = (try decode(Opt.child, reader, allocator)).unwrap(&out.bytes_read);
    } else {
        out.value = null;
    }

    return out;
}

fn decodeEnum(comptime E: std.builtin.Type.Enum, comptime Enum: type, reader: anytype, allocator: std.mem.Allocator) !Decoded(Enum) {
    const Tag = E.tag_type;

    // allow an enum to define a function craftDecodeTag(DeserializeType) Tag
    //
    // if this function is defined, we will deserialize the type of the first argument,
    // then call craftDecodeTag with that value, and use the returned Tag with
    // @enumFromInt
    const decode_tag_fn_name = "craftDecodeTag";
    if (std.meta.hasFn(Enum, decode_tag_fn_name)) {
        const f = @field(Enum, decode_tag_fn_name);
        const fn_info = @typeInfo(@TypeOf(f)).@"fn";
        if (fn_info.params.len != 1) {
            @compileError(@typeName(Enum) ++ "." ++ decode_tag_fn_name ++ "must accept exactly one parameter");
        }

        const WireTagType = fn_info.params[0].type.?;
        const ReturnType = fn_info.return_type.?;

        // decode a value, using the type of the first parameter for craftDecodeTag
        const wire_tag_info: Decoded(WireTagType) = try decode(WireTagType, reader, allocator);
        const bytes_read: usize = wire_tag_info.bytes_read;
        const wire_tag: WireTagType = wire_tag_info.value;
        defer if (std.meta.hasFn(WireTagType, "deinit")) {
            wire_tag.deinit();
        };

        // call craftDecodeTag(WireTag) -> ??
        const decoded_tag: ReturnType = @call(.auto, f, .{wire_tag});

        // now try to interpret the ReturnType
        const enum_value = calc_enum_value: {
            switch (ReturnType) {
                Tag => break :calc_enum_value (try std.meta.intToEnum(Enum, decoded_tag)),
                Enum => break :calc_enum_value decoded_tag,
                else => {
                    switch (@typeInfo(ReturnType)) {
                        .error_union => |EU| {
                            const EUPld = EU.payload;
                            const non_error: EUPld = try decoded_tag;
                            switch (EUPld) {
                                Tag => break :calc_enum_value try std.meta.intToEnum(Enum, non_error),
                                Enum => break :calc_enum_value non_error,
                                else => {},
                            }
                        },
                        else => {},
                    }
                },
            }

            @compileError("return type " ++ @typeName(ReturnType) ++ " for " ++ @typeName(Enum) ++ "." ++ decode_tag_fn_name ++ " is not supported");
        };
        return .{ .value = enum_value, .bytes_read = bytes_read };
    } else {
        const dcd = try decode(Tag, reader, allocator);
        const converted: Enum = try std.meta.intToEnum(Enum, dcd.value);
        return .{ .value = converted, .bytes_read = dcd.bytes_read };
    }
}

pub fn EnumTable(comptime Enum: type, comptime Item: type) type {
    return [@typeInfo(Enum).@"enum".fields.len]Item;
}

pub fn CraftEncodeStrEnum(enum_value: anytype, comptime TABLE: EnumTable(@TypeOf(enum_value), []const u8)) String {
    return String.init(TABLE[@intFromEnum(enum_value)]);
}

pub fn CraftDecodeStrEnum(comptime Enum: type, str: String, comptime TABLE: EnumTable(Enum, []const u8)) !Enum {
    const str_slice = str.constSlice();
    for (TABLE, 0..) |variant, idx| {
        if (std.mem.eql(u8, variant, str_slice)) {
            return @enumFromInt(idx);
        }
    }
    return error.BadEnumVariant;
}

pub fn AutoStringEnum(comptime Enum: type) type {
    return struct {
        const STRINGS_TABLE = AutoEnumStringsTable(Enum);

        pub fn craftEncodeTag(self: Enum) String {
            return CraftEncodeStrEnum(self, STRINGS_TABLE);
        }

        pub fn craftDecodeTag(tag: String) !Enum {
            return CraftDecodeStrEnum(Enum, tag, STRINGS_TABLE);
        }
    };
}

pub fn AutoVarNumEnum(comptime Enum: type, comptime VarNum: type) type {
    const TagType = @typeInfo(Enum).@"enum".tag_type;
    return struct {
        pub fn craftEncodeTag(self: TagType) VarNum {
            return @enumFromInt(self);
        }

        pub fn craftDecodeTag(tag: VarNum) TagType {
            return @intFromEnum(tag);
        }
    };
}

pub fn AutoEnumStringsTable(comptime Enum: type) [@typeInfo(Enum).@"enum".fields.len][]const u8 {
    comptime {
        var out: [@typeInfo(Enum).@"enum".fields.len][]const u8 = undefined;
        for (@typeInfo(Enum).@"enum".fields, 0..) |Field, idx| {
            out[idx] = Field.name;
        }
        return out;
    }
}

pub fn Cow(comptime Payload: type) type {
    return union(enum) {
        pub const Owned = struct {
            ptr: *Payload,
            allocator: std.mem.Allocator,
        };

        borrowed: *const Payload,
        owned: Owned,

        const Ctr = @This();

        pub fn init(data: *const Payload) Ctr {
            return .{ .borrowed = data };
        }

        pub fn borrow(ctr: Ctr) Ctr {
            return .{ .borrowed = ctr.constPtr() };
        }

        pub fn deinit(ctr: Ctr) void {
            switch (ctr) {
                .owned => |o| {
                    if (std.meta.hasFn(Payload, "deinit")) {
                        o.ptr.*.deinit();
                    }

                    o.allocator.destroy(o.ptr);
                },
                .borrowed => {},
            }
        }

        pub fn constPtr(ctr: Ctr) *const Payload {
            return switch (ctr) {
                .owned => |o| o.ptr,
                .borrowed => |ptr| ptr,
            };
        }

        pub fn craftEncode(ctr: Ctr, writer: anytype) !usize {
            return encode(ctr.constPtr(), writer);
        }

        pub fn craftDecode(reader: anytype, allocator: std.mem.Allocator) !Decoded(Ctr) {
            const owned_ptr: *Payload = try allocator.create(Payload);
            const dcd = try decode(Payload, reader, allocator);
            owned_ptr.* = dcd.value;
            return .{
                .value = .{
                    .owned = .{
                        .ptr = owned_ptr,
                        .allocator = allocator,
                    },
                },
                .bytes_read = dcd.bytes_read,
            };
        }
    };
}

pub fn CowSlice(comptime Payload: type) type {
    return union(enum) {
        pub const Owned = struct {
            ptr: []Payload,
            allocator: std.mem.Allocator,
        };

        borrowed: []const Payload,
        owned: Owned,

        const Ctr = @This();

        pub fn borrow(ctr: Ctr) Ctr {
            return .{ .borrowed = ctr.constSlice() };
        }

        pub fn deinit(ctr: Ctr) void {
            switch (ctr) {
                .owned => |o| {
                    if (std.meta.hasFn(Payload, "deinit")) {
                        for (o.ptr) |item| {
                            item.deinit();
                        }
                    }

                    o.allocator.free(o.ptr);
                },
                else => {},
            }
        }

        pub fn constSlice(ctr: *const Ctr) []const Payload {
            return switch (ctr.*) {
                .owned => |o| o.ptr,
                .borrowed => |b| b,
            };
        }

        pub fn craftEncode(ctr: Ctr, writer: anytype) !usize {
            return encode(ctr.constSlice(), writer);
        }

        fn craftDecodeN(num: usize, reader: anytype, allocator: std.mem.Allocator) !Decoded(Ctr) {
            const slice: []Payload = try allocator.alloc(Payload, num);
            var bytes: usize = 0;
            if (Payload == u8) {
                try reader.readNoEof(slice);
                bytes = slice.len;
            } else {
                for (0..num) |idx| {
                    slice[idx] = (try decode(Payload, reader, allocator)).unwrap(&bytes);
                }
            }
            return .{
                .bytes_read = bytes,
                .value = .{
                    .owned = .{
                        .ptr = slice,
                        .allocator = allocator,
                    },
                },
            };
        }
    };
}

pub fn LengthPrefixed(comptime Counter: type, comptime Payload: type) type {
    return struct {
        items: ItemsSlice,

        const Ctr = @This();
        pub const EMPTY: Ctr = .init(&.{});
        const ItemsSlice = CowSlice(Payload);

        pub fn init(items: []const Payload) Ctr {
            return .{ .items = .{ .borrowed = items } };
        }

        pub fn borrow(ctr: Ctr) Ctr {
            return .{ .items = ctr.items.borrow() };
        }

        pub fn deinit(ctr: Ctr) void {
            ctr.items.deinit();
        }

        pub fn craftEncode(ctr: Ctr, writer: anytype) !usize {
            const items = ctr.constSlice();
            var bytes: usize = 0;

            bytes += try encode(@as(Counter, @enumFromInt(items.len)), writer);
            bytes += try encode(ctr.items, writer);
            return bytes;
        }

        pub fn craftDecode(reader: anytype, allocator: std.mem.Allocator) !Decoded(Ctr) {
            var bytes: usize = 0;
            const counter: Counter = (try decode(Counter, reader, allocator)).unwrap(&bytes);
            const items: ItemsSlice = (try ItemsSlice.craftDecodeN(@intCast(@intFromEnum(counter)), reader, allocator)).unwrap(&bytes);
            return .{ .bytes_read = bytes, .value = .{ .items = items } };
        }

        pub fn constSlice(ctr: *const Ctr) []const Payload {
            return ctr.items.constSlice();
        }
    };
}

pub const String = LengthPrefixed(VarInt, u8);

test "encode string" {
    const test_data = "hello world";

    const craft_str = String.init(test_data);
    defer craft_str.deinit();

    var buf = std.ArrayList(u8).init(std.testing.allocator);
    defer buf.deinit();

    const bytes_written = try encode(craft_str, buf.writer());
    try std.testing.expectEqual(test_data.len + 1, bytes_written);
    try std.testing.expectEqualSlices(u8, &.{
        0x0B, // 11
        0x68, 0x65, 0x6C, 0x6C, 0x6F, // hello
        0x20, // space
        0x77, 0x6F, 0x72, 0x6C, 0x64, // world
    }, buf.items);
}

test "decode string" {
    const test_data: []const u8 = &.{
        0x0B, // 11
        0x68, 0x65, 0x6C, 0x6C, 0x6F, // hello
        0x20, // space
        0x77, 0x6F, 0x72, 0x6C, 0x64, // world
    };

    var stream = std.io.fixedBufferStream(test_data);
    const decoded = try decode(String, stream.reader(), std.testing.allocator);
    const str_cow = decoded.value;
    defer str_cow.deinit();
    try std.testing.expectEqual(test_data.len, decoded.bytes_read);
    const str: []const u8 = str_cow.constSlice();
    try std.testing.expectEqualStrings("hello world", str);
}

test "handshaking packet" {
    const HandshakingPacket = struct {
        version: VarInt,
        address: String,
        port: u16,
        nextState: enum(i32) {
            status = 1,
            login = 2,
            transfer = 3,

            pub usingnamespace AutoVarNumEnum(@This(), VarInt);
        },

        fn deinit(self: @This()) void {
            self.address.deinit();
        }
    };

    const pkt: HandshakingPacket = .{
        .version = @enumFromInt(770),
        .address = .init("localhost"),
        .port = 25565,
        .nextState = .status,
    };

    var buf = std.ArrayList(u8).init(std.testing.allocator);
    defer buf.deinit();

    const num_bytes = try encode(pkt, buf.writer());

    var stream = std.io.fixedBufferStream(buf.items);
    const decoded: Decoded(HandshakingPacket) = try decode(HandshakingPacket, stream.reader(), std.testing.allocator);
    const hs_pkt_decoded = decoded.value;
    defer hs_pkt_decoded.deinit();
    const hs_bytes_read = decoded.bytes_read;

    try std.testing.expectEqual(num_bytes, hs_bytes_read);
    try std.testing.expectEqual(pkt.version, hs_pkt_decoded.version);
    try std.testing.expectEqualStrings(pkt.address.constSlice(), hs_pkt_decoded.address.constSlice());
    try std.testing.expectEqual(pkt.port, hs_pkt_decoded.port);
    try std.testing.expectEqual(pkt.nextState, hs_pkt_decoded.nextState);
}

test "string enum" {
    const NameTagVisibility = enum {
        always,
        hideForOtherTeams,
        hideForOwnTeam,
        never,

        pub usingnamespace AutoStringEnum(@This());
    };

    // test encode and decode for "hideForOtherTeams" (should encode as the string "hideForOtherTeams")
    var buf = std.ArrayList(u8).init(std.testing.allocator);
    defer buf.deinit();
    const v: NameTagVisibility = .hideForOtherTeams;
    _ = try encode(v, buf.writer());

    var reader_stream = std.io.fixedBufferStream(buf.items);
    const decoded: NameTagVisibility = (try decode(NameTagVisibility, reader_stream.reader(), std.testing.allocator)).unwrap(null);
    try std.testing.expectEqual(v, decoded);
}

pub const UUID = struct {
    pub const NUM_BYTES: usize = 16;

    raw: [NUM_BYTES]u8,

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

    pub fn craftEncode(uuid: UUID, writer: anytype) !usize {
        try writer.writeAll(&uuid.raw);
        return NUM_BYTES;
    }

    pub fn craftDecode(reader: anytype, _: std.mem.Allocator) !Decoded(UUID) {
        var out: UUID = undefined;
        try reader.readNoEof(&out.raw);
        return .{ .bytes_read = NUM_BYTES, .value = out };
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
            var out: [NUM_BYTES]u8 = undefined;
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
    try std.testing.expectEqual(UUID.NUM_BYTES, bytes);
    try std.testing.expectEqualStrings(&id0.raw, buf.items);
}

pub fn RestOfPacketArray(comptime Payload: type) type {
    return struct {
        items: ItemSlice,

        pub const ItemSlice = CowSlice(Payload);

        const Ctr = @This();

        pub const EMPTY: Ctr = .init(&.{});

        pub fn init(in: []const Payload) Ctr {
            return .{ .items = .{ .borrowed = in } };
        }

        pub fn deinit(self: Ctr) void {
            self.items.deinit();
        }

        pub fn craftEncode(self: Ctr, writer: anytype) !usize {
            return self.items.craftEncode(writer);
        }

        pub fn craftDecode(reader: anytype, allocator: std.mem.Allocator) !Decoded(Ctr) {
            if (Payload == u8) {
                // we own this memory
                const out: Ctr = .{
                    .items = .{
                        .owned = .{
                            .ptr = (try reader.readAllAlloc(allocator, MAX_PACKET_SIZE)),
                            .allocator = allocator,
                        },
                    },
                };
                return .{
                    .bytes_read = out.constSlice().len,
                    .value = out,
                };
            } else {
                var buf = std.ArrayList(Payload).init(allocator);
                defer buf.deinit();

                var bytes: usize = 0;
                read_items: while (true) {
                    const next: Payload = (decode(Payload, reader, allocator) catch |err| switch (err) {
                        error.EndOfStream => break :read_items,
                        else => return err,
                    }).unwrap(&bytes);

                    buf.append(next);
                }

                return .{
                    .bytes_read = bytes,
                    .value = .{
                        .items = .{
                            .owned = .{
                                .allocator = allocator,
                                .items = try buf.toOwnedSlice(),
                            },
                        },
                    },
                };
            }
        }

        pub fn constSlice(self: *const Ctr) []const Payload {
            return self.items.constSlice();
        }
    };
}

pub const RemainingBytes = RestOfPacketArray(u8);
