const std = @import("std");
const Diag = @This();
pub const diag_log_scope = .diag;
const diag_log = std.log.scoped(diag_log_scope);

pub const Error = error{
    DiagTooDeep,
};

state: ?*State = null,
path_next_idx: usize = 0,

pub const MAX_DIAG_DEPTH: usize = 32;

pub fn child(diag: Diag, component: PathComponent) Error!Diag {
    if (diag.state) |s| {
        const next_idx = diag.path_next_idx + 1;
        if (next_idx >= MAX_DIAG_DEPTH) {
            return error.DiagTooDeep;
        }

        s.path[diag.path_next_idx] = component;
        return .{ .state = s, .path_next_idx = next_idx };
    } else {
        return diag;
    }
}

fn at(diag: Diag) []const PathComponent {
    if (diag.state) |state| {
        return state.path[0..diag.path_next_idx];
    } else {
        return &.{};
    }
}

pub fn report(
    diag: Diag,
    code: anyerror,
    comptime typ: []const u8,
    comptime msg: []const u8,
    args: anytype,
) void {
    if (diag.state) |state| {
        var msg_buf = std.ArrayList(u8).init(state.arena.allocator());
        msg_buf.writer().print(msg, args) catch {
            return;
        };

        state.report(.{
            .at = diag.at(),
            .code = code,
            .type = typ,
            .message = msg_buf.toOwnedSlice() catch "error printing error... bro",
        });
    }
}

pub fn ok(
    diag: Diag,
    comptime typ: []const u8,
    comptime op: []const u8,
    bytes: usize,
    comptime fmt: []const u8,
    args: anytype,
) void {
    if (std.log.logEnabled(.debug, diag_log_scope)) {
        if (diag.state) |state| {
            if (state.report_ok) {
                var buf = std.ArrayList(u8).init(state.arena.allocator());
                defer buf.deinit();

                formatPath(diag.at(), buf.writer()) catch {
                    diag_log.debug("{s} {s} = " ++ fmt ++ " ({d} bytes)", .{ typ, op } ++ args ++ .{bytes});
                    return;
                };

                diag_log.debug("{s} {s} {s} = " ++ fmt ++ " ({d} bytes)", .{ buf.items, typ, op } ++ args ++ .{bytes});
            }
        }
    }
}

pub const PathComponent = union(enum) {
    packet_length,
    packet_data_length,
    packet_id,
    packet_body,
    field: [*:0]const u8,
    tag,
    optional_prefix,
    payload,
    length_prefix,
    index: usize,
};

pub const Report = struct {
    at: []const PathComponent,
    code: anyerror,
    type: []const u8,
    message: []const u8,

    pub fn format(
        r: Report,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fmt;
        _ = options;

        try formatPath(r.at, writer);

        if (r.at.len > 0) {
            try writer.writeAll(" ");
        }
        if (r.type.len > 0) {
            try writer.print("{s} ", .{r.type});
        }
        try writer.print(
            "--> code = {any}, msg = {s}",
            .{
                r.code,
                r.message,
            },
        );
    }
};

fn formatPath(path: []const PathComponent, writer: anytype) !void {
    for (path) |component| {
        switch (component) {
            .packet_length => try writer.writeAll("packet.length"),
            .packet_data_length => try writer.writeAll("packet.data_length"),
            .packet_id => try writer.writeAll("packet.id"),
            .packet_body => try writer.writeAll("packet.body"),
            .field => |field_name| try writer.print(".{s}", .{field_name}),
            .tag => try writer.writeAll("|Tag"),
            .payload => {},
            .length_prefix => try writer.writeAll("|LengthPrefix"),
            .optional_prefix => try writer.writeAll("|OptionalPrefix"),
            .index => |idx| try writer.print("[{d}]", .{idx}),
        }
    }
}

pub const State = struct {
    report_ok: bool,
    reports: std.ArrayList(Report),
    arena: *std.heap.ArenaAllocator,
    path: [MAX_DIAG_DEPTH]PathComponent = undefined,

    pub fn init(report_ok: bool, arena: *std.heap.ArenaAllocator) State {
        return .{
            .report_ok = report_ok,
            .reports = std.ArrayList(Report).init(arena.allocator()),
            .arena = arena,
        };
    }

    pub fn diag(state: *State) Diag {
        return .{ .state = state };
    }

    fn report(state: *State, r: Report) void {
        state.reports.append(r) catch {};
    }
};
