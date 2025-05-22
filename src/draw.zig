const std = @import("std");
const zigimg = @import("zigimg");
const craft_packets = @import("packets.zig");
const Favicon = craft_packets.Favicon;

pub const FaviconPrinter = struct {
    options: Options,
    image: zigimg.Image,

    pub const Options = struct {
        columns: u16 = 16,
        rows: u16 = 16,
    };

    pub fn init(favicon: Favicon, options: Options, allocator: std.mem.Allocator) !FaviconPrinter {
        if (!std.ascii.eqlIgnoreCase(favicon.mime_type, "image/png")) {
            return error.UnsupportedImageType;
        }

        var stream = std.io.StreamSource{
            .const_buffer = std.io.fixedBufferStream(favicon.image),
        };

        return .{
            .options = options,
            .image = (try zigimg.formats.png.load(
                &stream,
                allocator,
                .{},
            )).toManaged(allocator),
        };
    }

    pub fn deinit(self: FaviconPrinter) void {
        self.image.deinit();
    }

    pub fn draw(self: FaviconPrinter, writer: anytype) !void {
        for (0..self.options.rows) |y| {
            for (0..self.options.columns) |x| {
                try self.drawOne(writer, @intCast(x), @intCast(y));
            }
            try writer.writeByte('\n');
        }
        try writeResetControl(writer);
    }

    fn drawOne(self: FaviconPrinter, writer: anytype, x: u16, y: u16) !void {
        if (self.colorForCell(x, y)) |col| {
            try writeColorControl(writer, col);
        } else {
            return error.CannotCalculateColor;
        }
        try writer.writeAll("▓▓");
    }

    fn writeColorControl(writer: anytype, color: zigimg.color.Colorf32) !void {
        const r = zigimg.color.toIntColor(u8, color.r);
        const g = zigimg.color.toIntColor(u8, color.g);
        const b = zigimg.color.toIntColor(u8, color.b);
        try writeControl(writer, "38;2;{d};{d};{d}", .{ r, g, b });
    }

    fn writeResetControl(writer: anytype) !void {
        try writeControl(writer, "0", .{});
    }

    fn writeControl(writer: anytype, comptime fmt: []const u8, args: anytype) !void {
        try writer.writeByte(0x1B);
        try writer.writeByte('[');
        try writer.print(fmt, args);
        try writer.writeByte('m');
    }

    fn colorForCell(self: FaviconPrinter, x: u16, y: u16) ?zigimg.color.Colorf32 {
        var row_iter: PixelIndexIter = .{
            .src = self.image.pixels,
            .src_width = self.image.width,
            .src_height = self.image.height,
            .target_width = @intCast(self.options.columns),
            .target_height = @intCast(self.options.rows),
            .target_x = x,
            .target_y = y,
        };

        var average: zigimg.math.float4 = @splat(0.0);
        average[3] = 1.0; // alpha = 1

        const weight = 1.0 / @as(f32, @floatFromInt(row_iter.size()));
        while (row_iter.next()) |row| {
            var pixel_iter = zigimg.color.PixelStorageIterator.init(&row);
            while (pixel_iter.next()) |pix| {
                var pixel = pix.toFloat4();
                pixel[3] = 1.0; // alpha always 1.0
                pixel *= @splat(weight);
                average += pixel;
            }
        }

        return zigimg.color.Colorf32.fromFloat4(average);
    }
};

const PixelIndexIter = struct {
    src: zigimg.color.PixelStorage,
    src_width: usize,
    src_height: usize,

    target_width: usize,
    target_height: usize,

    target_x: u16,
    target_y: u16,

    index: usize = 0,

    pub fn next(self: *@This()) ?zigimg.color.PixelStorage {
        if (self.index >= self.size()) {
            return null;
        }

        const x_size = self.src_width / self.target_width;
        const y_size = self.src_height / self.target_height;

        const x0 = x_size * self.target_x;
        const y0 = y_size * self.target_y;

        const row = (self.index / x_size) + y0;
        const col = (self.index % x_size) + x0;

        const start_index = (row * self.src_width) + col;
        const span_size = x_size;
        const end_index = start_index + span_size;
        self.index += span_size;
        return self.src.slice(start_index, end_index);
    }

    pub fn size(self: *const @This()) usize {
        const x_size = self.src_width / self.target_width;
        const y_size = self.src_height / self.target_height;
        return x_size * y_size;
    }
};
