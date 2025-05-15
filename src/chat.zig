const std = @import("std");
const craft_io = @import("io.zig");
const UUID = @import("UUID.zig");

pub const Component = struct {
    content: Content,
    color: ?Color = null,
    font: ?[]const u8 = null,
    bold: ?bool = null,
    italic: ?bool = null,
    underlined: ?bool = null,
    strikethrough: ?bool = null,
    obfuscated: ?bool = null,
    // todo shadow_color
    insertion: ?[]const u8 = null,
    click_event: ?ClickEvent = null,
    hover_event: ?HoverEvent = null,
    extra: ?[]const Component = null,

    pub const CraftEncoding: type = craft_io.JsonEncoding;

    pub fn jsonParse(
        allocator: std.mem.Allocator,
        source: *std.json.Scanner,
        options: std.json.ParseOptions,
    ) !Component {
        switch (try source.peekNextTokenType()) {
            .object_begin => {
                @panic("todo");
            },
            .string => {
                return switch (try source.nextAllocMax(
                    allocator,
                    .alloc_always,
                    options.max_value_len.?,
                )) {
                    inline .string, .allocated_string => |s| .{ .content = .{ .text = s } },
                    else => error.UnexpectedToken,
                };
            },
            else => return error.UnexpectedToken,
        }
    }
};

pub const ColorType = enum { builtin, hex };

pub const Color = union(ColorType) { builtin: BuiltinColor, hex: HexColor };

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

pub const HexColor = struct { r: u8, g: u8, b: u8 };

pub const ComponentType = enum {
    text,
    translatable,
    score,
    selector,
    keybind,
    // todo
    // nbt,
};

pub const Content = union(ComponentType) {
    text: []const u8,
    translatable: TranslatedTextContent,
    score: ScoreContent,
    selector: SelectorContent,
    keybind: KeybindContent,
    // nbt: NBTContent, todo
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
    separator: *const Component = &.{ .content = .{ .text = "" } },
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
    // todo components
    // components
};

pub const ShowEntityAction = struct {
    name: ?[]const u8,
    id: []const u8,
    // todo uuid
    uuid: UUID,
};
