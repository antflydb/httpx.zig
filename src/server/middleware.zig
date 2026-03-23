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
const Context = @import("server.zig").Context;
const Response = @import("../core/response.zig").Response;
const types = @import("../core/types.zig");
const milliTimestamp = @import("../util/common.zig").milliTimestamp;

/// Middleware function type.
pub const Middleware = struct {
    handler: *const fn (*Context, Next) anyerror!Response,
    name: []const u8 = "unnamed",
};

/// Next function to call the next middleware.
pub const Next = *const fn (*Context) anyerror!Response;

/// CORS configuration.
pub const CorsConfig = struct {
    allowed_origins: []const []const u8 = &[_][]const u8{"*"},
    allowed_methods: []const types.Method = &[_]types.Method{ .GET, .POST, .PUT, .DELETE, .PATCH, .OPTIONS },
    allowed_headers: []const []const u8 = &[_][]const u8{ "Content-Type", "Authorization" },
    exposed_headers: []const []const u8 = &[_][]const u8{},
    allow_credentials: bool = false,
    max_age: u32 = 86400,
};

/// Creates CORS middleware.
pub fn cors(config: CorsConfig) Middleware {
    return .{
        .name = "cors",
        .handler = struct {
            fn methodList(allocator: std.mem.Allocator, methods: []const types.Method) ![]u8 {
                var out = std.ArrayListUnmanaged(u8).empty;
                errdefer out.deinit(allocator);
                const writer = arrayListWriter(&out, allocator);

                for (methods, 0..) |m, i| {
                    if (i > 0) try writer.writeAll(", ");
                    try writer.writeAll(m.toString());
                }
                return out.toOwnedSlice(allocator);
            }

            fn headerList(allocator: std.mem.Allocator, headers_in: []const []const u8) ![]u8 {
                var out = std.ArrayListUnmanaged(u8).empty;
                errdefer out.deinit(allocator);
                const writer = arrayListWriter(&out, allocator);

                for (headers_in, 0..) |h, i| {
                    if (i > 0) try writer.writeAll(", ");
                    try writer.writeAll(h);
                }
                return out.toOwnedSlice(allocator);
            }

            fn allowedOrigin(ctx: *Context, cfg: CorsConfig) []const u8 {
                const req_origin = ctx.header("Origin") orelse return cfg.allowed_origins[0];
                for (cfg.allowed_origins) |o| {
                    if (std.mem.eql(u8, o, "*") or std.mem.eql(u8, o, req_origin)) {
                        return if (std.mem.eql(u8, o, "*")) "*" else req_origin;
                    }
                }
                return cfg.allowed_origins[0];
            }

            fn handler(ctx: *Context, next: Next) anyerror!Response {
                const origin = allowedOrigin(ctx, config);
                try ctx.setHeader("Access-Control-Allow-Origin", origin);
                try ctx.setHeader("Vary", "Origin");

                const methods = try methodList(ctx.allocator, config.allowed_methods);
                defer ctx.allocator.free(methods);
                try ctx.setHeader("Access-Control-Allow-Methods", methods);

                const allowed_headers = try headerList(ctx.allocator, config.allowed_headers);
                defer ctx.allocator.free(allowed_headers);
                try ctx.setHeader("Access-Control-Allow-Headers", allowed_headers);

                if (config.exposed_headers.len > 0) {
                    const exposed = try headerList(ctx.allocator, config.exposed_headers);
                    defer ctx.allocator.free(exposed);
                    try ctx.setHeader("Access-Control-Expose-Headers", exposed);
                }

                if (config.allow_credentials) {
                    try ctx.setHeader("Access-Control-Allow-Credentials", "true");
                }

                var max_age_buf: [32]u8 = undefined;
                const max_age = std.fmt.bufPrint(&max_age_buf, "{d}", .{config.max_age}) catch unreachable;
                try ctx.setHeader("Access-Control-Max-Age", max_age);

                if (ctx.request.method == .OPTIONS) {
                    return ctx.status(204).text("");
                }

                return next(ctx);
            }
        }.handler,
    };
}

/// Creates logging middleware.
pub fn logger() Middleware {
    return .{
        .name = "logger",
        .handler = struct {
            fn handler(ctx: *Context, next: Next) anyerror!Response {
                const start = milliTimestamp();
                const response = try next(ctx);
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
            fn handler(ctx: *Context, next: Next) anyerror!Response {
                try ctx.setHeader("X-Content-Type-Options", "nosniff");
                try ctx.setHeader("X-Frame-Options", "SAMEORIGIN");
                try ctx.setHeader("X-XSS-Protection", "0");
                try ctx.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
                return next(ctx);
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

            fn handler(ctx: *Context, next_handler: Next) anyerror!Response {
                const id = counter.fetchAdd(1, .monotonic);
                var buf: [16]u8 = undefined;
                const hex = std.fmt.bufPrint(&buf, "{x:0>16}", .{id}) catch unreachable;
                try ctx.setHeader("X-Request-ID", hex);
                return next_handler(ctx);
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
