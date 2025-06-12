const std = @import("std");

pub fn hasPrefix(comptime T: type, haystack: []const T, prefix: []const T) bool {
    return haystack.len >= prefix.len and std.mem.eql(T, haystack[0..prefix.len], prefix);
}

pub fn stripPrefix(comptime T: type, haystack: *[]const T, prefix: []const T) bool {
    if (hasPrefix(T, haystack.*, prefix)) {
        haystack.* = haystack.*[prefix.len..];
        return true;
    } else {
        return false;
    }
}

pub fn decodeHexChar(c: u8) ?u4 {
    return switch (c) {
        '0'...'9' => @intCast(c - '0'),
        'a'...'f' => @as(u4, @intCast(c - 'a')) + 10,
        'A'...'F' => @as(u4, @intCast(c - 'A')) + 10,
        else => null,
    };
}

pub fn hexCharFor(hb: u4) u8 {
    if (hb < 10) {
        return @as(u8, @intCast(hb)) + '0';
    } else {
        return @as(u8, @intCast(hb - 10)) + 'a';
    }
}

pub fn shouldDiagPrintBytes(bs: []const u8) bool {
    if (bs.len > 2048) {
        return false;
    }

    for (bs) |b| {
        if (!std.ascii.isPrint(b)) {
            return false;
        }
    }
    return true;
}
