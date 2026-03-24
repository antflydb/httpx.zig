//! HTTP Middleware Support for httpx.zig
//!
//! Provides middleware functionality for HTTP servers:
//!
//! - CORS (Cross-Origin Resource Sharing)
//! - Logging and request timing
//! - Rate limiting
//! - Basic authentication
//! - Security headers (Helmet)
//! - Response compression
//! - Body parsing

const std = @import("std");
const arrayListWriter = @import("../util/array_list_writer.zig").arrayListWriter;
const common = @import("../util/common.zig");
const Context = @import("server.zig").Context;
const Response = @import("../core/response.zig").Response;
const types = @import("../core/types.zig");
const HeaderName = @import("../core/headers.zig").HeaderName;
const milliTimestamp = @import("../util/common.zig").milliTimestamp;

/// Middleware function type.
pub const Middleware = struct {
    handler: *const fn (*Context, *Next) anyerror!Response,
    name: []const u8 = "unnamed",
};

/// Opaque handle for calling the next middleware in the chain.
/// Middleware receives a `*Next` and calls `next.call(ctx)` to proceed.
pub const Next = struct {
    _call: *const fn (*Next, *Context) anyerror!Response,

    pub fn call(self: *Next, ctx: *Context) anyerror!Response {
        return self._call(self, ctx);
    }
};

/// CORS configuration.
pub const CorsConfig = struct {
    allowed_origins: []const []const u8 = &[_][]const u8{"*"},
    allowed_methods: []const types.Method = &[_]types.Method{ .GET, .POST, .PUT, .DELETE, .PATCH, .OPTIONS },
    allowed_headers: []const []const u8 = &[_][]const u8{ "Content-Type", "Authorization" },
    exposed_headers: []const []const u8 = &[_][]const u8{},
    allow_credentials: bool = false,
    max_age: u32 = 86400,
};

/// Joins comptime-known string slices with a separator at compile time.
fn comptimeJoin(comptime parts: []const []const u8, comptime sep: []const u8) []const u8 {
    comptime {
        if (parts.len == 0) return "";
        var len: usize = 0;
        for (parts, 0..) |p, i| {
            if (i > 0) len += sep.len;
            len += p.len;
        }
        var buf: [len]u8 = undefined;
        var pos: usize = 0;
        for (parts, 0..) |p, i| {
            if (i > 0) {
                @memcpy(buf[pos..][0..sep.len], sep);
                pos += sep.len;
            }
            @memcpy(buf[pos..][0..p.len], p);
            pos += p.len;
        }
        return &buf;
    }
}

/// Converts a comptime method slice to a string slice of their names.
fn comptimeMethodNames(comptime methods: []const types.Method) []const []const u8 {
    comptime {
        var names: [methods.len][]const u8 = undefined;
        for (methods, 0..) |m, i| {
            names[i] = m.toString();
        }
        return &names;
    }
}

/// Creates CORS middleware. Config must be comptime-known so header strings
/// are precomputed at compile time — zero per-request allocations.
pub fn cors(comptime config: CorsConfig) Middleware {
    return .{
        .name = "cors",
        .handler = struct {
            const methods_str = comptimeJoin(comptimeMethodNames(config.allowed_methods), ", ");
            const headers_str = comptimeJoin(config.allowed_headers, ", ");
            const exposed_str = comptimeJoin(config.exposed_headers, ", ");
            const max_age_str = std.fmt.comptimePrint("{d}", .{config.max_age});

            fn allowedOrigin(ctx: *Context) []const u8 {
                const req_origin = ctx.header("Origin") orelse return config.allowed_origins[0];
                for (config.allowed_origins) |o| {
                    if (std.mem.eql(u8, o, "*") or std.mem.eql(u8, o, req_origin)) {
                        return if (std.mem.eql(u8, o, "*")) "*" else req_origin;
                    }
                }
                return config.allowed_origins[0];
            }

            fn handler(ctx: *Context, next: *Next) anyerror!Response {
                const origin = allowedOrigin(ctx);
                try ctx.setHeader(HeaderName.ACCESS_CONTROL_ALLOW_ORIGIN, origin);
                try ctx.setHeader(HeaderName.VARY, "Origin");
                try ctx.setHeader(HeaderName.ACCESS_CONTROL_ALLOW_METHODS, methods_str);
                try ctx.setHeader(HeaderName.ACCESS_CONTROL_ALLOW_HEADERS, headers_str);

                if (config.exposed_headers.len > 0) {
                    try ctx.setHeader(HeaderName.ACCESS_CONTROL_EXPOSE_HEADERS, exposed_str);
                }

                if (config.allow_credentials) {
                    try ctx.setHeader(HeaderName.ACCESS_CONTROL_ALLOW_CREDENTIALS, "true");
                }

                try ctx.setHeader(HeaderName.ACCESS_CONTROL_MAX_AGE, max_age_str);

                if (ctx.request.method == .OPTIONS) {
                    return ctx.status(204).text("");
                }

                return next.call(ctx);
            }
        }.handler,
    };
}

/// Creates logging middleware.
pub fn logger() Middleware {
    return .{
        .name = "logger",
        .handler = struct {
            fn handler(ctx: *Context, next: *Next) anyerror!Response {
                const start = milliTimestamp();
                const response = try next.call(ctx);
                const duration = milliTimestamp() - start;

                std.debug.print("{s} {s} - {d}ms\n", .{
                    ctx.request.method.toString(),
                    ctx.request.uri.path,
                    duration,
                });

                return response;
            }
        }.handler,
    };
}

/// Rate limiting configuration.
pub const RateLimitConfig = struct {
    max_requests: u32 = 100,
    window_ms: u64 = 60_000,
};

/// Creates security headers middleware (Helmet).
/// Sets common security headers on every response.
pub fn helmet() Middleware {
    return .{
        .name = "helmet",
        .handler = struct {
            fn handler(ctx: *Context, next: *Next) anyerror!Response {
                try ctx.setHeader(HeaderName.X_CONTENT_TYPE_OPTIONS, "nosniff");
                try ctx.setHeader(HeaderName.X_FRAME_OPTIONS, "SAMEORIGIN");
                try ctx.setHeader(HeaderName.X_XSS_PROTECTION, "0");
                try ctx.setHeader(HeaderName.REFERRER_POLICY, "strict-origin-when-cross-origin");
                return next.call(ctx);
            }
        }.handler,
    };
}

/// Creates request ID middleware.
/// Generates a unique hex ID per request using a monotonic counter.
pub fn requestId() Middleware {
    return .{
        .name = "request_id",
        .handler = struct {
            var counter = std.atomic.Value(u64).init(0);

            fn handler(ctx: *Context, next_handler: *Next) anyerror!Response {
                const id = counter.fetchAdd(1, .monotonic);
                var buf: [16]u8 = undefined;
                const hex = std.fmt.bufPrint(&buf, "{x:0>16}", .{id}) catch unreachable;
                try ctx.setHeader(HeaderName.X_REQUEST_ID, hex);
                return next_handler.call(ctx);
            }
        }.handler,
    };
}

test "Middleware creation" {
    const mw = logger();
    try std.testing.expectEqualStrings("logger", mw.name);
}

test "CORS middleware" {
    const config = CorsConfig{};
    const mw = cors(config);
    try std.testing.expectEqualStrings("cors", mw.name);
}

test "Helmet middleware" {
    const mw = helmet();
    try std.testing.expectEqualStrings("helmet", mw.name);
}
