//! Encoding Utilities for httpx.zig
//!
//! Provides encoding and decoding utilities commonly used in HTTP:
//!
//! - Base64 encoding/decoding for Authorization headers
//! - Hexadecimal encoding for checksums and tokens
//! - URL percent-encoding for query strings and path segments
//! - Form data encoding (application/x-www-form-urlencoded)

const std = @import("std");
const arrayListWriter = @import("array_list_writer.zig").arrayListWriter;
const Allocator = std.mem.Allocator;

/// Base64 encoding and decoding per RFC 4648.
pub const Base64 = struct {
    const standard = std.base64.standard;
    const url_safe = std.base64.url_safe_no_pad;

    /// Encodes data to standard Base64.
    pub fn encode(allocator: Allocator, data: []const u8) ![]u8 {
        const len = standard.Encoder.calcSize(data.len);
        const result = try allocator.alloc(u8, len);
        _ = standard.Encoder.encode(result, data);
        return result;
    }

    /// Decodes Base64 data.
    pub fn decode(allocator: Allocator, data: []const u8) ![]u8 {
        const len = standard.Decoder.calcSizeForSlice(data) catch return error.InvalidBase64;
        const result = try allocator.alloc(u8, len);
        standard.Decoder.decode(result, data) catch return error.InvalidBase64;
        return result;
    }

    /// Encodes to URL-safe Base64 (no padding).
    pub fn encodeUrl(allocator: Allocator, data: []const u8) ![]u8 {
        const len = url_safe.Encoder.calcSize(data.len);
        const result = try allocator.alloc(u8, len);
        _ = url_safe.Encoder.encode(result, data);
        return result;
    }
};

/// Hexadecimal encoding and decoding.
pub const Hex = struct {
    const hex_chars = "0123456789abcdef";

    /// Encodes data to lowercase hexadecimal.
    pub fn encode(allocator: Allocator, data: []const u8) ![]u8 {
        const result = try allocator.alloc(u8, data.len * 2);
        for (data, 0..) |byte, i| {
            result[i * 2] = hex_chars[byte >> 4];
            result[i * 2 + 1] = hex_chars[byte & 0x0F];
        }
        return result;
    }

    /// Decodes hexadecimal data.
    pub fn decode(allocator: Allocator, data: []const u8) ![]u8 {
        if (data.len % 2 != 0) return error.InvalidHex;

        const result = try allocator.alloc(u8, data.len / 2);
        var i: usize = 0;
        while (i < data.len) {
            const high = hexValue(data[i]) orelse return error.InvalidHex;
            const low = hexValue(data[i + 1]) orelse return error.InvalidHex;
            result[i / 2] = (high << 4) | low;
            i += 2;
        }
        return result;
    }

    fn hexValue(c: u8) ?u8 {
        if (c >= '0' and c <= '9') return c - '0';
        if (c >= 'a' and c <= 'f') return c - 'a' + 10;
        if (c >= 'A' and c <= 'F') return c - 'A' + 10;
        return null;
    }
};

/// URL percent-encoding per RFC 3986.
pub const PercentEncoding = struct {
    /// Comptime lookup table: true if byte is unreserved (RFC 3986 §2.3).
    const unreserved_table: [256]bool = blk: {
        var table = [_]bool{false} ** 256;
        for ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~") |c| {
            table[c] = true;
        }
        break :blk table;
    };

    /// Encodes a string for use in URLs.
    pub fn encode(allocator: Allocator, input: []const u8) ![]u8 {
        var result = std.ArrayListUnmanaged(u8).empty;
        const writer = arrayListWriter(&result, allocator);

        for (input) |c| {
            if (unreserved_table[c]) {
                try writer.writeByte(c);
            } else {
                try writer.print("%{X:0>2}", .{c});
            }
        }

        return result.toOwnedSlice(allocator);
    }

    /// Decodes a percent-encoded string per RFC 3986.
    /// For form-data decoding (where '+' maps to space), use `decodeFormData`.
    pub fn decode(allocator: Allocator, input: []const u8) ![]u8 {
        return decodeInternal(allocator, input, false);
    }

    /// Decodes a percent-encoded string with '+' → space (application/x-www-form-urlencoded).
    pub fn decodeFormData(allocator: Allocator, input: []const u8) ![]u8 {
        return decodeInternal(allocator, input, true);
    }

    fn decodeInternal(allocator: Allocator, input: []const u8, plus_as_space: bool) ![]u8 {
        var result = std.ArrayListUnmanaged(u8).empty;

        var i: usize = 0;
        while (i < input.len) {
            if (input[i] == '%' and i + 2 < input.len) {
                const hex = input[i + 1 .. i + 3];
                if (std.fmt.parseInt(u8, hex, 16)) |byte| {
                    try result.append(allocator, byte);
                    i += 3;
                    continue;
                } else |_| {}
            }
            if (plus_as_space and input[i] == '+') {
                try result.append(allocator, ' ');
            } else {
                try result.append(allocator, input[i]);
            }
            i += 1;
        }

        return result.toOwnedSlice(allocator);
    }
};

/// Encodes key-value pairs as application/x-www-form-urlencoded.
pub fn encodeFormData(allocator: Allocator, params: []const struct { []const u8, []const u8 }) ![]u8 {
    var result = std.ArrayListUnmanaged(u8).empty;
    const writer = arrayListWriter(&result, allocator);

    for (params, 0..) |param, idx| {
        if (idx > 0) try writer.writeByte('&');
        const key = try PercentEncoding.encode(allocator, param[0]);
        defer allocator.free(key);
        const value = try PercentEncoding.encode(allocator, param[1]);
        defer allocator.free(value);
        try writer.print("{s}={s}", .{ key, value });
    }

    return result.toOwnedSlice(allocator);
}

test "Base64 encode" {
    const allocator = std.testing.allocator;

    const encoded = try Base64.encode(allocator, "Hello");
    defer allocator.free(encoded);
    try std.testing.expectEqualStrings("SGVsbG8=", encoded);
}

test "Base64 decode" {
    const allocator = std.testing.allocator;

    const decoded = try Base64.decode(allocator, "SGVsbG8=");
    defer allocator.free(decoded);
    try std.testing.expectEqualStrings("Hello", decoded);
}

test "Base64 roundtrip" {
    const allocator = std.testing.allocator;
    const original = "The quick brown fox!";

    const encoded = try Base64.encode(allocator, original);
    defer allocator.free(encoded);
    const decoded = try Base64.decode(allocator, encoded);
    defer allocator.free(decoded);

    try std.testing.expectEqualStrings(original, decoded);
}

test "Base64 URL-safe encode" {
    const allocator = std.testing.allocator;

    const encoded = try Base64.encodeUrl(allocator, "\xfb\xff\xfe");
    defer allocator.free(encoded);
    // URL-safe: no +, /, or = characters
    for (encoded) |c| {
        try std.testing.expect(c != '+' and c != '/' and c != '=');
    }
}

test "Hex encode" {
    const allocator = std.testing.allocator;

    const encoded = try Hex.encode(allocator, "\x00\xff\x10");
    defer allocator.free(encoded);
    try std.testing.expectEqualStrings("00ff10", encoded);
}

test "Hex decode" {
    const allocator = std.testing.allocator;

    const decoded = try Hex.decode(allocator, "48656c6c6f");
    defer allocator.free(decoded);
    try std.testing.expectEqualStrings("Hello", decoded);
}

test "Percent encoding" {
    const allocator = std.testing.allocator;

    const encoded = try PercentEncoding.encode(allocator, "hello world!");
    defer allocator.free(encoded);
    try std.testing.expectEqualStrings("hello%20world%21", encoded);
}

test "Percent decoding" {
    const allocator = std.testing.allocator;

    const decoded = try PercentEncoding.decode(allocator, "hello%20world");
    defer allocator.free(decoded);
    try std.testing.expectEqualStrings("hello world", decoded);
}

test "Form data encoding" {
    const allocator = std.testing.allocator;

    const encoded = try encodeFormData(allocator, &.{
        .{ "name", "John Doe" },
        .{ "email", "john@example.com" },
    });
    defer allocator.free(encoded);

    try std.testing.expect(std.mem.indexOf(u8, encoded, "name=John%20Doe") != null);
}
