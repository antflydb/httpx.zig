//! HTTP Headers Implementation for httpx.zig
//!
//! Provides a high-performance, case-insensitive HTTP header storage with
//! multi-value support per RFC 7230. Features include:
//!
//! - Case-insensitive header name lookups
//! - Multiple values per header name (e.g., Set-Cookie)
//! - Efficient serialization for wire format
//! - Common header name constants for compile-time optimization
//! - Memory-safe ownership model with automatic cleanup

const std = @import("std");
const arrayListWriter = @import("../util/array_list_writer.zig").arrayListWriter;
const mem = std.mem;
const Allocator = mem.Allocator;
const types = @import("types.zig");

/// Standard HTTP header name constants.
/// Using these constants enables compile-time string interning.
pub const HeaderName = struct {
    pub const ACCEPT = "Accept";
    pub const ACCEPT_CHARSET = "Accept-Charset";
    pub const ACCEPT_ENCODING = "Accept-Encoding";
    pub const ACCEPT_LANGUAGE = "Accept-Language";
    pub const AUTHORIZATION = "Authorization";
    pub const CACHE_CONTROL = "Cache-Control";
    pub const CONNECTION = "Connection";
    pub const CONTENT_DISPOSITION = "Content-Disposition";
    pub const CONTENT_ENCODING = "Content-Encoding";
    pub const CONTENT_LENGTH = "Content-Length";
    pub const CONTENT_TYPE = "Content-Type";
    pub const COOKIE = "Cookie";
    pub const DATE = "Date";
    pub const ETAG = "ETag";
    pub const EXPIRES = "Expires";
    pub const HOST = "Host";
    pub const IF_MATCH = "If-Match";
    pub const IF_MODIFIED_SINCE = "If-Modified-Since";
    pub const IF_NONE_MATCH = "If-None-Match";
    pub const LAST_MODIFIED = "Last-Modified";
    pub const LOCATION = "Location";
    pub const ORIGIN = "Origin";
    pub const PRAGMA = "Pragma";
    pub const PROXY_AUTHORIZATION = "Proxy-Authorization";
    pub const RANGE = "Range";
    pub const REFERER = "Referer";
    pub const RETRY_AFTER = "Retry-After";
    pub const SERVER = "Server";
    pub const SET_COOKIE = "Set-Cookie";
    pub const STRICT_TRANSPORT_SECURITY = "Strict-Transport-Security";
    pub const TRANSFER_ENCODING = "Transfer-Encoding";
    pub const UPGRADE = "Upgrade";
    pub const USER_AGENT = "User-Agent";
    pub const VARY = "Vary";
    pub const WWW_AUTHENTICATE = "WWW-Authenticate";
    pub const X_CONTENT_TYPE_OPTIONS = "X-Content-Type-Options";
    pub const X_FRAME_OPTIONS = "X-Frame-Options";
    pub const X_XSS_PROTECTION = "X-XSS-Protection";
};

/// Represents a single HTTP header entry.
pub const Header = struct {
    name: []const u8,
    value: []const u8,
    owned: bool = false,
};

/// HTTP headers collection with case-insensitive lookups.
pub const Headers = struct {
    allocator: Allocator,
    entries: std.ArrayListUnmanaged(Header) = .empty,

    const Self = @This();

    /// Creates a new empty Headers instance.
    pub fn init(allocator: Allocator) Self {
        return .{ .allocator = allocator };
    }

    /// Releases all allocated memory.
    pub fn deinit(self: *Self) void {
        for (self.entries.items) |entry| {
            if (entry.owned) {
                self.allocator.free(entry.name);
                self.allocator.free(entry.value);
            }
        }
        self.entries.deinit(self.allocator);
    }

    /// Appends a header, allowing multiple values for the same name.
    pub fn append(self: *Self, name: []const u8, value: []const u8) !void {
        const owned_name = try self.allocator.dupe(u8, name);
        errdefer self.allocator.free(owned_name);
        const owned_value = try self.allocator.dupe(u8, value);
        try self.entries.append(self.allocator, .{
            .name = owned_name,
            .value = owned_value,
            .owned = true,
        });
    }

    /// Sets a header, replacing any existing values with the same name.
    pub fn set(self: *Self, name: []const u8, value: []const u8) !void {
        self.removeAll(name);
        try self.append(name, value);
    }

    /// Retrieves the first value for a header name (case-insensitive).
    pub fn get(self: *const Self, name: []const u8) ?[]const u8 {
        for (self.entries.items) |entry| {
            if (eqlIgnoreCase(entry.name, name)) return entry.value;
        }
        return null;
    }

    /// Returns all values for a header name.
    pub fn getAll(self: *const Self, name: []const u8, allocator: Allocator) ![][]const u8 {
        var values = std.ArrayListUnmanaged([]const u8).empty;
        for (self.entries.items) |entry| {
            if (eqlIgnoreCase(entry.name, name)) {
                try values.append(allocator, entry.value);
            }
        }
        return values.toOwnedSlice(allocator);
    }

    /// Returns true if the header exists.
    pub fn contains(self: *const Self, name: []const u8) bool {
        return self.get(name) != null;
    }

    /// Removes the first occurrence of a header.
    pub fn remove(self: *Self, name: []const u8) bool {
        for (self.entries.items, 0..) |entry, i| {
            if (eqlIgnoreCase(entry.name, name)) {
                if (entry.owned) {
                    self.allocator.free(entry.name);
                    self.allocator.free(entry.value);
                }
                _ = self.entries.orderedRemove(i);
                return true;
            }
        }
        return false;
    }

    /// Removes all occurrences of a header.
    pub fn removeAll(self: *Self, name: []const u8) void {
        var i: usize = 0;
        while (i < self.entries.items.len) {
            if (eqlIgnoreCase(self.entries.items[i].name, name)) {
                const entry = self.entries.orderedRemove(i);
                if (entry.owned) {
                    self.allocator.free(entry.name);
                    self.allocator.free(entry.value);
                }
            } else i += 1;
        }
    }

    /// Returns the number of headers.
    pub fn count(self: *const Self) usize {
        return self.entries.items.len;
    }

    /// Returns an iterator over all headers.
    pub fn iterator(self: *const Self) []const Header {
        return self.entries.items;
    }

    /// Clears all headers.
    pub fn clear(self: *Self) void {
        for (self.entries.items) |entry| {
            if (entry.owned) {
                self.allocator.free(entry.name);
                self.allocator.free(entry.value);
            }
        }
        self.entries.clearRetainingCapacity();
    }

    /// Creates a deep copy of the headers.
    pub fn clone(self: *const Self, allocator: Allocator) !Headers {
        var new_headers = Headers.init(allocator);
        for (self.entries.items) |entry| {
            try new_headers.append(entry.name, entry.value);
        }
        return new_headers;
    }

    /// Sets the Content-Length header from a numeric value.
    pub fn setContentLength(self: *Self, len: usize) !void {
        var buf: [32]u8 = undefined;
        const str = std.fmt.bufPrint(&buf, "{d}", .{len}) catch unreachable;
        try self.set(HeaderName.CONTENT_LENGTH, str);
    }

    /// Parses Content-Length header value.
    pub fn getContentLength(self: *const Self) ?u64 {
        const value = self.get(HeaderName.CONTENT_LENGTH) orelse return null;
        return std.fmt.parseInt(u64, value, 10) catch null;
    }

    /// Returns true if Transfer-Encoding includes chunked.
    /// Uses token-list parsing per RFC 7230 §3.3.1.
    pub fn isChunked(self: *const Self) bool {
        const value = self.get(HeaderName.TRANSFER_ENCODING) orelse return false;
        return containsToken(value, "chunked");
    }

    /// Determines if connection should be kept alive based on headers and version.
    /// Parses the Connection header as a comma-separated token list per RFC 7230 §6.1.
    pub fn isKeepAlive(self: *const Self, version: types.Version) bool {
        const conn = self.get(HeaderName.CONNECTION);
        if (conn) |c| {
            if (containsToken(c, "close")) return false;
            if (containsToken(c, "keep-alive")) return true;
        }
        return version == .HTTP_1_1 or version == .HTTP_2 or version == .HTTP_3;
    }

    /// Serializes headers to HTTP wire format.
    /// Returns error.HeaderContainsCrLf if any name or value contains CR/LF.
    pub fn serialize(self: *const Self, writer: anytype) !void {
        for (self.entries.items) |entry| {
            if (containsCrLf(entry.name) or containsCrLf(entry.value)) return error.HeaderContainsCrLf;
            try writer.print("{s}: {s}\r\n", .{ entry.name, entry.value });
        }
    }

    /// Serializes headers to an allocated string.
    pub fn toSlice(self: *const Self, allocator: Allocator) ![]u8 {
        var buffer = std.ArrayListUnmanaged(u8).empty;
        const writer = arrayListWriter(&buffer, allocator);
        try self.serialize(writer);
        return buffer.toOwnedSlice(allocator);
    }
};

/// Case-insensitive string comparison for ASCII.
const eqlIgnoreCase = std.ascii.eqlIgnoreCase;

/// Returns true if `header_value` contains `token` as a comma-separated,
/// whitespace-trimmed, case-insensitive token per RFC 7230 §3.2.6.
fn containsToken(header_value: []const u8, token: []const u8) bool {
    var it = mem.splitScalar(u8, header_value, ',');
    while (it.next()) |part| {
        const trimmed = mem.trim(u8, part, " \t");
        if (eqlIgnoreCase(trimmed, token)) return true;
    }
    return false;
}

fn containsCrLf(s: []const u8) bool {
    return mem.indexOfScalar(u8, s, '\r') != null or mem.indexOfScalar(u8, s, '\n') != null;
}

test "Headers basic operations" {
    const allocator = std.testing.allocator;
    var headers = Headers.init(allocator);
    defer headers.deinit();

    try headers.append("Content-Type", "application/json");
    try std.testing.expectEqualStrings("application/json", headers.get("Content-Type").?);
}

test "Headers case insensitivity" {
    const allocator = std.testing.allocator;
    var headers = Headers.init(allocator);
    defer headers.deinit();

    try headers.append("Content-Type", "text/html");
    try std.testing.expectEqualStrings("text/html", headers.get("content-type").?);
    try std.testing.expectEqualStrings("text/html", headers.get("CONTENT-TYPE").?);
}

test "Headers set replaces existing" {
    const allocator = std.testing.allocator;
    var headers = Headers.init(allocator);
    defer headers.deinit();

    try headers.append("X-Test", "value1");
    try headers.set("X-Test", "value2");
    try std.testing.expectEqualStrings("value2", headers.get("X-Test").?);
    try std.testing.expectEqual(@as(usize, 1), headers.count());
}

test "Headers multiple values" {
    const allocator = std.testing.allocator;
    var headers = Headers.init(allocator);
    defer headers.deinit();

    try headers.append("Set-Cookie", "cookie1=value1");
    try headers.append("Set-Cookie", "cookie2=value2");
    try std.testing.expectEqual(@as(usize, 2), headers.count());
}

test "Headers Content-Length parsing" {
    const allocator = std.testing.allocator;
    var headers = Headers.init(allocator);
    defer headers.deinit();

    try headers.set("Content-Length", "12345");
    try std.testing.expectEqual(@as(u64, 12345), headers.getContentLength().?);
}

test "Headers keep-alive detection" {
    const allocator = std.testing.allocator;
    var headers = Headers.init(allocator);
    defer headers.deinit();

    try std.testing.expect(headers.isKeepAlive(.HTTP_1_1));
    try std.testing.expect(!headers.isKeepAlive(.HTTP_1_0));

    try headers.set("Connection", "keep-alive");
    try std.testing.expect(headers.isKeepAlive(.HTTP_1_0));
}
