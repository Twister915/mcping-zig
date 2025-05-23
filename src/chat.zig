const std = @import("std");
const craft_io = @import("io.zig");
const UUID = @import("UUID.zig");
const util = @import("util.zig");

// raw data-type definitions
pub const Component = struct {
    // TODO use the Content struct once I figure out better JSON parsing... I can't really use union(enum) yet
    // content: Content,
    text: ?[]const u8 = null,
    color: ?Color = null,
    font: ?[]const u8 = null,
    bold: ?bool = null,
    italic: ?bool = null,
    underlined: ?bool = null,
    strikethrough: ?bool = null,
    obfuscated: ?bool = null,
    // TODO shadow_color
    // TODO fix interactivity (these use enums discriminated on "type" which is hard to parse)
    // insertion: ?[]const u8 = null,
    // click_event: ?ClickEvent = null,
    // hover_event: ?HoverEvent = null,
    extra: ?[]const Component = null,

    pub const EMPTY: Component = .{ .text = "" };

    pub const CraftEncoding: type = craft_io.JsonEncoding;

    const ComponentBase = @Type(.{ .@"struct" = .{
        .layout = .auto,
        .fields = @typeInfo(Component).@"struct".fields,
        .decls = &.{},
        .is_tuple = false,
    } });

    pub fn jsonParse(
        allocator: std.mem.Allocator,
        source: anytype,
        options: std.json.ParseOptions,
    ) !Component {
        const tt = try source.peekNextTokenType();
        switch (tt) {
            .object_begin => {
                return fromBase(try std.json.innerParse(
                    ComponentBase,
                    allocator,
                    source,
                    options,
                ));
            },
            .string => {
                const s = try std.json.innerParse(
                    []const u8,
                    allocator,
                    source,
                    options,
                );
                return .{ .text = s };
            },
            else => {
                std.debug.print("error processing JSON from status, got token {any}\n", .{tt});
                return error.UnexpectedToken;
            },
        }
    }

    fn fromBase(inner: ComponentBase) Component {
        var out: Component = undefined;
        inline for (@typeInfo(@This()).@"struct".fields) |field| {
            @field(out, field.name) = @field(inner, field.name);
        }
        return out;
    }

    pub fn format(
        self: Component,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fmt;
        _ = options;

        var iter = self.textIter(.{ .translate_traditional = true });
        while (try iter.next()) |node| {
            try writer.print("{s}", .{node.text});
        }
    }

    pub fn textIter(self: Component, options: TextIterOptions) TextIter {
        return TextIter.init(self, options);
    }
};

pub const ColorType = enum { builtin, hex };

pub const Color = union(ColorType) {
    builtin: BuiltinColor,
    hex: HexColor,

    pub fn jsonParse(
        allocator: std.mem.Allocator,
        source: anytype,
        options: std.json.ParseOptions,
    ) !Color {
        const color_name = try std.json.innerParse([]const u8, allocator, source, options);
        if (std.meta.stringToEnum(BuiltinColor, color_name)) |builtin| {
            return .{ .builtin = builtin };
        } else if (HexColor.parseHexColor(color_name)) |hex_color| {
            return .{ .hex = hex_color };
        } else {
            return error.UnexpectedToken;
        }
    }
};

pub const BuiltinColor = enum {
    black,
    dark_blue,
    dark_green,
    dark_aqua,
    dark_red,
    dark_purple,
    gold,
    gray,
    dark_gray,
    blue,
    green,
    aqua,
    red,
    light_purple,
    yellow,
    white,
};

pub const HexColor = struct {
    r: u8,
    g: u8,
    b: u8,

    fn parseHexColor(raw: []const u8) ?HexColor {
        if (raw.len != 7) return null;
        if (raw[0] != '#') return null;
        var rest = raw[1..];
        const r = decodeHexByte(&rest) orelse return null;
        const g = decodeHexByte(&rest) orelse return null;
        const b = decodeHexByte(&rest) orelse return null;
        return .{ .r = r, .g = g, .b = b };
    }

    fn decodeHexByte(slice_ptr: *[]const u8) ?u8 {
        const data = slice_ptr.*;
        var out: u8 = undefined;
        out |= @as(u8, @intCast(util.decodeHexChar(data[0]) orelse return null)) << 4;
        out |= @intCast(util.decodeHexChar(data[1]) orelse return null);
        slice_ptr.* = data[2..];
        return out;
    }
};

pub const ComponentType = enum {
    text,
    translatable,
    score,
    selector,
    keybind,
    // TODO nbt
};

pub const Content = union(ComponentType) {
    text: []const u8,
    translatable: TranslatedTextContent,
    score: ScoreContent,
    selector: SelectorContent,
    keybind: KeybindContent,
    // TODO nbt: NBTContent
};

pub const TranslatedTextContent = struct {
    translate: []const u8,
    fallback: ?[]const u8,
    with: ?[]const Component,
};

pub const ScoreContent = struct {
    name: []const u8,
    objective: []const u8,
};

pub const SelectorContent = struct {
    selector: []const u8,
    separator: *const Component = &Component.EMPTY,
};

pub const KeybindContent = struct { keybind: []const u8 };

pub const ClickAcitonType = enum {
    open_url,
    open_file,
    run_command,
    suggest_command,
    change_page,
    copy_to_clipboard,
};

pub const ClickEvent = union(ClickAcitonType) {
    open_url: OpenURLAction,
    open_file: OpenFileAction,
    run_command: CommandAction,
    suggest_command: CommandAction,
    change_page: ChangePageAction,
    copy_to_clipboard: CopyToClipboardAction,
};

pub const OpenURLAction = struct { url: []const u8 };
pub const OpenFileAction = struct { path: []const u8 };
pub const CommandAction = struct { command: []const u8 };
pub const ChangePageAction = struct { page: i32 };
pub const CopyToClipboardAction = struct { value: []const u8 };

pub const HoverEventType = enum { show_text, show_item, show_entity };
pub const HoverEvent = union(HoverEventType) {
    show_text: *const Component,
    show_item: ShowItemAction,
    show_entity: ShowEntityAction,
};

pub const ShowItemAction = struct {
    id: []const u8,
    count: i32,
    // TODO components
};

pub const ShowEntityAction = struct {
    name: ?[]const u8,
    id: []const u8,
    // TODO uuid
    uuid: UUID,
};

// text iterator for printing, with formatting and interactivity
pub const TextNode = struct {
    text: []const u8,
    formatting: Formatting,
    interactivity: Interactivity,
};

pub const Formatting = struct {
    color: ?Color = null,
    font: ?[]const u8 = null,
    bold: bool = false,
    italic: bool = false,
    underlined: bool = false,
    strikethrough: bool = false,
    obfuscated: bool = false,
    // TODO shadow_color

    pub fn isEmpty(self: Formatting) bool {
        return areAllFieldsDefault(self);
    }
};

pub const Interactivity = struct {
    // insertion: ?[]const u8 = null,
    // click_event: ?ClickEvent = null,
    // hover_event: ?HoverEvent = null,

    pub fn isEmpty(self: Interactivity) bool {
        return areAllFieldsDefault(self);
    }
};

fn areAllFieldsDefault(data: anytype) bool {
    inline for (@typeInfo(@TypeOf(data)).@"struct".fields) |field_info| {
        switch (@typeInfo(field_info.type)) {
            .optional => {
                if (@field(data, field_info.name) != null) {
                    return false;
                }
            },
            .bool => {
                if (@field(data, field_info.name) != field_info.defaultValue().?) {
                    return false;
                }
            },
            else => @compileError("cannot use areAllFieldsDefault for " ++ @typeName(@TypeOf(data)) ++ "." ++ field_info.name),
        }
    }

    return true;
}

pub const TextIterOptions = struct {
    translate_traditional: bool = true,
    // cleanup_spaces: bool = false, TODO
};

pub const TextIter = struct {
    const Frame = struct {
        node: Component,
        traditional: ?TraditionalParser = null,
        state: union(enum) {
            root,
            extra_node: usize,
            finished,
        } = .root,
    };

    // the 16 here is the maximum depth of "extra"
    const Frames = std.BoundedArray(Frame, 16);

    frames: Frames = .{},
    options: TextIterOptions,

    const Self = @This();

    fn init(component: Component, options: TextIterOptions) Self {
        var out: Self = .{ .options = options };
        out.childFrameWithNode(component, true) catch unreachable;
        return out;
    }

    fn next(self: *Self) !?TextNode {
        state_loop: while (self.currentFrame()) |frame| {
            switch (frame.state) {
                .root => {
                    if (frame.traditional) |*traditional| {
                        if (traditional.next()) |parsed_next| {
                            try self.childFrameWithNode(parsed_next, false);
                            continue :state_loop;
                        }
                    }

                    if (frame.node.extra != null and frame.node.extra.?.len > 0) {
                        frame.state = .{ .extra_node = 0 };
                    } else {
                        frame.state = .finished;
                    }

                    if (frame.traditional == null) {
                        if (frame.node.text) |text| {
                            if (text.len > 0) {
                                return self.textNode(text);
                            }
                        }
                    }
                },

                .extra_node => |extra_idx| {
                    if (frame.node.extra) |extra| {
                        if (extra.len > extra_idx) {
                            try self.childFrameWithNode(extra[extra_idx], true);
                            const next_idx = extra_idx + 1;
                            if (extra.len > next_idx) {
                                frame.state = .{ .extra_node = next_idx };
                                continue :state_loop;
                            }
                        }
                    }

                    frame.state = .finished;
                },

                .finished => {
                    _ = self.frames.pop();
                },
            }
        }

        return null;
    }

    fn currentFrame(self: *Self) ?*Frame {
        const n = self.frames.slice().len;
        if (n == 0) {
            return null;
        }

        const idx = n - 1;
        return &self.frames.slice()[idx];
    }

    fn textNode(self: *Self, text: []const u8) TextNode {
        return .{
            .text = text,
            .formatting = self.formatting(),
            .interactivity = self.interactivity(),
        };
    }

    fn childFrameWithNode(self: *Self, node: Component, allow_translate_traditional: bool) !void {
        var next_frame: Frame = .{ .node = node };
        if (self.options.translate_traditional) {
            if (node.text) |txt| {
                if (allow_translate_traditional and !self.hasAnyFormattingOrInteractivity()) {
                    next_frame.traditional = .{ .text = txt };
                }
            }
        }

        try self.frames.append(next_frame);
    }

    fn hasAnyFormattingOrInteractivity(self: *const Self) bool {
        return !self.formatting().isEmpty() or !self.interactivity().isEmpty();
    }

    fn formatting(self: *const Self) Formatting {
        return self.fieldsFromAllFrames(Formatting);
    }

    fn interactivity(self: *const Self) Interactivity {
        return self.fieldsFromAllFrames(Interactivity);
    }

    fn fieldsFromAllFrames(self: *const Self, comptime Out: type) Out {
        const out_fields = @typeInfo(Out).@"struct".fields;
        var out: Out = .{};
        for (self.frames.constSlice()) |*frame| {
            const node = frame.node;
            inline for (out_fields) |field| {
                const node_value = @field(node, field.name);
                if (node_value) |non_null_node_value| {
                    @field(out, field.name) = non_null_node_value;
                }
            }
        }
        return out;
    }
};

pub const ParsedTraditional = struct {
    allocator: std.mem.Allocator,
    component: Component,
    components: ?[]Component = null,

    pub fn deinit(self: ParsedTraditional) void {
        if (self.components) |components| {
            self.allocator.free(components);
        }
    }
};

pub fn parseTraditional(traditional: []const u8, allocator: std.mem.Allocator) !ParsedTraditional {
    var parser: TraditionalParser = .{ .text = traditional };
    const first = parser.next() orelse Component.EMPTY;

    if (parser.next()) |second| {
        var extras = std.ArrayList(Component).init(allocator);
        errdefer extras.deinit();

        try extras.append(first);
        try extras.append(second);

        while (parser.next()) |next| {
            try extras.append(next);
        }
        const components = try extras.toOwnedSlice();
        const root_component: Component = .{
            .text = "",
            .extra = components,
        };
        return .{
            .component = root_component,
            .components = components,
            .allocator = allocator,
        };
    }

    return .{
        .component = first,
        .allocator = allocator,
    };
}

const TraditionalParser = struct {
    text: []const u8,
    formatting: Formatting = .{},

    const Self = @This();

    pub fn next(self: *Self) ?Component {
        if (self.text.len == 0) {
            return null;
        }

        const SECTION_SYMBOL = "§";
        const SECTION_SYMBOL_SIZE = SECTION_SYMBOL.len;

        while (util.hasPrefix(u8, self.text, SECTION_SYMBOL)) {
            if (self.text.len > SECTION_SYMBOL_SIZE) {
                switch (self.text[SECTION_SYMBOL_SIZE]) {
                    '0' => self.applyColor(.black),
                    '1' => self.applyColor(.dark_blue),
                    '2' => self.applyColor(.dark_green),
                    '3' => self.applyColor(.dark_aqua),
                    '4' => self.applyColor(.dark_red),
                    '5' => self.applyColor(.dark_purple),
                    '6' => self.applyColor(.gold),
                    '7' => self.applyColor(.gray),
                    '8' => self.applyColor(.dark_gray),
                    '9' => self.applyColor(.blue),
                    'a', 'A' => self.applyColor(.green),
                    'b', 'B' => self.applyColor(.aqua),
                    'c', 'C' => self.applyColor(.red),
                    'd', 'D' => self.applyColor(.light_purple),
                    'e', 'E' => self.applyColor(.yellow),
                    'f', 'F' => self.applyColor(.white),
                    'k', 'K' => self.formatting.obfuscated = true,
                    'l', 'L' => self.formatting.bold = true,
                    'm', 'M' => self.formatting.strikethrough = true,
                    'n', 'N' => self.formatting.underlined = true,
                    'o', 'O' => self.formatting.italic = true,
                    'r', 'R' => self.resetFormatting(),
                    else => return self.emit(SECTION_SYMBOL_SIZE + 1),
                }
                self.consume(SECTION_SYMBOL_SIZE + 1);
            } else {
                return self.emit(SECTION_SYMBOL_SIZE);
            }
        }

        if (std.mem.indexOf(u8, self.text, SECTION_SYMBOL)) |next_format_code_idx| {
            if (next_format_code_idx == 0) {
                @panic("should have consumed section symbol, but did not");
            }

            return self.emit(next_format_code_idx);
        }

        return self.emit(self.text.len);
    }

    fn applyColor(self: *Self, color: ?BuiltinColor) void {
        self.resetFormatting();
        self.formatting.color = if (color) |bc| .{
            .builtin = bc,
        } else null;
    }

    fn resetFormatting(self: *Self) void {
        self.formatting = .{};
    }

    fn emit(self: *Self, size: usize) Component {
        const text_to_emit = self.text[0..size];
        self.consume(size);
        return .{
            .text = text_to_emit,
            .color = self.formatting.color,
            .bold = self.formatting.bold,
            .italic = self.formatting.italic,
            .underlined = self.formatting.underlined,
            .strikethrough = self.formatting.strikethrough,
            .obfuscated = self.formatting.obfuscated,
        };
    }

    fn consume(self: *Self, size: usize) void {
        self.text = self.text[size..];
    }
};

test "traditional parser" {
    const example = "§aHypixel Network §c[1.8-1.21]";
    var parser: TraditionalParser = .{ .text = example };
    const expected: [2]Component = .{
        .{
            .text = "Hypixel Network ",
            .color = .{ .builtin = .green },
            .bold = false,
            .italic = false,
            .underlined = false,
            .strikethrough = false,
            .obfuscated = false,
        },
        .{
            .text = "[1.8-1.21]",
            .color = .{ .builtin = .red },
            .bold = false,
            .italic = false,
            .underlined = false,
            .strikethrough = false,
            .obfuscated = false,
        },
    };
    for (expected) |e| {
        if (parser.next()) |next| {
            try std.testing.expectEqualDeep(e, next);
        } else {
            return error.TooFewTextComponents;
        }
    }
    try std.testing.expectEqual(null, parser.next());
}

pub const BashWriteOptions = struct {
    no_style: bool = false,
};

pub fn writeBash(
    component: Component,
    text_options: TextIterOptions,
    bash_options: BashWriteOptions,
    target: anytype,
) !void {
    const Writer = BashWriter(@TypeOf(target));
    var writer = Writer.init(component, text_options, bash_options, target);
    try writer.flush();
}

fn BashWriter(comptime W: type) type {
    return struct {
        target: W,
        text_iter: TextIter,
        options: BashWriteOptions,

        formatting: Formatting = .{},
        styles_changed: bool = false,
        colors_changed: bool = false,
        any_control_codes_emitted: bool = false,

        const Self = @This();

        pub fn init(
            component: Component,
            text_options: TextIterOptions,
            bash_options: BashWriteOptions,
            target: W,
        ) Self {
            return .{
                .target = target,
                .text_iter = TextIter.init(component, text_options),
                .options = bash_options,
            };
        }

        pub fn flush(self: *Self) !void {
            while (try self.writeNext()) {}
            if (self.any_control_codes_emitted) {
                try self.writeControl("0", .{});
            }
        }

        fn writeNext(self: *Self) !bool {
            if (try self.text_iter.next()) |next_text| {
                // apply formatting
                inline for (@typeInfo(Formatting).@"struct".fields) |field_info| {
                    const value_from_next_text = @field(next_text.formatting, field_info.name);
                    const current_value = &@field(self.formatting, field_info.name);
                    if (comptime std.mem.eql(u8, field_info.name, "color")) {
                        // TODO this is not ideal, but can't do == between two ?Color
                        if (value_from_next_text != null) {
                            self.colors_changed = true;
                            current_value.* = value_from_next_text;
                        }
                    } else if (comptime std.mem.eql(u8, field_info.name, "font")) {
                        // TODO font??
                    } else {
                        if (value_from_next_text != current_value.*) {
                            self.styles_changed = true;
                            current_value.* = value_from_next_text;
                        }
                    }
                }

                try self.writeControls();
                try self.target.writeAll(next_text.text);
                return true;
            } else {
                return false;
            }
        }

        fn writeControls(self: *Self) !void {
            if (self.styles_changed) {
                try self.writeControl("0", .{});

                if (self.formatting.bold) {
                    try self.writeControl("1", .{});
                }

                if (self.formatting.underlined) {
                    try self.writeControl("4", .{});
                }

                if (self.formatting.obfuscated) {
                    try self.writeControl("6", .{});
                }

                if (self.formatting.strikethrough) {
                    try self.writeControl("9", .{});
                }

                self.styles_changed = false;
            }

            if (self.colors_changed) {
                try self.writeColor();
                self.colors_changed = false;
            }
        }

        fn writeColor(self: *Self) !void {
            if (self.formatting.color) |color| {
                switch (color) {
                    .builtin => |bc| try self.writeControl("{s}", .{switch (bc) {
                        .black => "30",
                        .dark_blue => "34",
                        .dark_green => "32",
                        .dark_aqua => "36",
                        .dark_red => "31",
                        .dark_purple => "35",
                        .gold => "33",
                        .gray => "37",
                        .dark_gray => "90",
                        .blue => "94",
                        .green => "92",
                        .aqua => "96",
                        .red => "91",
                        .light_purple => "95",
                        .yellow => "93",
                        .white => "97",
                    }}),
                    .hex => |hc| try self.writeControl("38;2;{d};{d};{d}", .{ hc.r, hc.g, hc.b }),
                }
            } else {
                try self.writeControl("39", .{});
            }
        }

        fn writeControl(self: *Self, comptime fmt: []const u8, args: anytype) !void {
            if (!self.options.no_style) {
                try self.target.writeByte(0x1B);
                try self.target.writeByte('[');
                try self.target.print(fmt, args);
                try self.target.writeByte('m');
                self.any_control_codes_emitted = true;
            }
        }
    };
}
