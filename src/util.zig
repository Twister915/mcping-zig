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
