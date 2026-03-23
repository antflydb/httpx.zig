//! HTTP Server Implementation for httpx.zig
//!
//! Production-ready HTTP server with comprehensive features:
//!
//! - Pattern-based routing with path parameters
//! - Middleware stack support
//! - Context-based request handling
//! - JSON response helpers
//! - Static file serving
//! - Cross-platform (Linux, Windows, macOS)

const std = @import("std");
const builtin = @import("builtin");
const arrayListWriter = @import("../util/array_list_writer.zig").arrayListWriter;
const mem = std.mem;
const Allocator = mem.Allocator;
const Io = std.Io;

/// Monotonic millisecond timestamp for request deadline tracking.
fn milliTimestamp() i64 {
    if (builtin.os.tag == .macos) {
        return @intCast(std.c.mach_absolute_time() / std.time.ns_per_ms);
    } else {
        var ts: std.c.timespec = undefined;
        _ = std.c.clock_gettime(std.c.CLOCK.MONOTONIC, &ts);
        return @as(i64, ts.sec) * 1000 + @divFloor(@as(i64, ts.nsec), std.time.ns_per_ms);
    }
}

const types = @import("../core/types.zig");
const Request = @import("../core/request.zig").Request;
const Response = @import("../core/response.zig").Response;
const ResponseBuilder = @import("../core/response.zig").ResponseBuilder;
const Headers = @import("../core/headers.zig").Headers;
const HeaderName = @import("../core/headers.zig").HeaderName;
const Parser = @import("../protocol/parser.zig").Parser;
const http = @import("../protocol/http.zig");
const Socket = @import("../net/socket.zig").Socket;
const Address = @import("../net/socket.zig").Address;
const TcpListener = @import("../net/socket.zig").TcpListener;
const Router = @import("router.zig").Router;
const Middleware = @import("middleware.zig").Middleware;
const common = @import("../util/common.zig");

pub const CookieOptions = common.CookieOptions;
pub const SameSite = common.SameSite;

/// SSE event payload used by `Context.sse`.
pub const SseEvent = struct {
    data: []const u8,
    event: ?[]const u8 = null,
    id: ?[]const u8 = null,
    retry_ms: ?u32 = null,
};

/// Pre-route hook called after parsing the request and before route matching.
pub const PreRouteHook = *const fn (*Context) anyerror!void;

/// Server configuration.
pub const ServerConfig = struct {
    host: []const u8 = "127.0.0.1",
    port: u16 = 8080,
    max_body_size: usize = 10 * 1024 * 1024,
    max_headers: usize = 100,
    max_file_size: usize = 100 * 1024 * 1024,
    request_timeout_ms: u64 = 30_000,
    keep_alive_timeout_ms: u64 = 60_000,
    max_connections: u32 = 1000,
    keep_alive: bool = true,
    threads: u32 = 0,
};

/// Request context passed to handlers.
pub const Context = struct {
    allocator: Allocator,
    request: *Request,
    response: ResponseBuilder,
    params: std.StringHashMap([]const u8),
    data: std.StringHashMap(*anyopaque),
    max_file_size: usize = 100 * 1024 * 1024,

    const Self = @This();

    /// Creates a new context for a request.
    pub fn init(allocator: Allocator, req: *Request) Self {
        return .{
            .allocator = allocator,
            .request = req,
            .response = ResponseBuilder.init(allocator),
            .params = std.StringHashMap([]const u8).init(allocator),
            .data = std.StringHashMap(*anyopaque).init(allocator),
        };
    }

    /// Releases context resources.
    pub fn deinit(self: *Self) void {
        self.response.deinit();
        self.params.deinit();
        self.data.deinit();
    }

    /// Returns a URL parameter by name.
    pub fn param(self: *const Self, name: []const u8) ?[]const u8 {
        return self.params.get(name);
    }

    /// Returns a query parameter by name.
    pub fn query(self: *const Self, name: []const u8) ?[]const u8 {
        const query_str = self.request.uri.query orelse return null;
        return common.queryValue(query_str, name);
    }

    /// Returns a request header by name.
    pub fn header(self: *const Self, name: []const u8) ?[]const u8 {
        return self.request.headers.get(name);
    }

    /// Returns a parsed cookie value by name from the request Cookie header.
    pub fn cookie(self: *const Self, name: []const u8) ?[]const u8 {
        const cookie_header = self.request.headers.get(HeaderName.COOKIE) orelse return null;
        return common.cookieValue(cookie_header, name);
    }

    /// Sets the response status code.
    pub fn status(self: *Self, code: u16) *Self {
        _ = self.response.status(code);
        return self;
    }

    /// Sets a response header.
    pub fn setHeader(self: *Self, name: []const u8, value: []const u8) !void {
        _ = try self.response.header(name, value);
    }

    /// Appends a Set-Cookie header with common cookie attributes.
    pub fn setCookie(self: *Self, name: []const u8, value: []const u8, options: CookieOptions) !void {
        const set_cookie = try common.buildSetCookieHeader(self.allocator, name, value, options);
        defer self.allocator.free(set_cookie);
        try self.response.headers.append(HeaderName.SET_COOKIE, set_cookie);
    }

    /// Appends a Set-Cookie header that removes a cookie via Max-Age=0.
    pub fn removeCookie(self: *Self, name: []const u8, options: CookieOptions) !void {
        var remove_options = options;
        remove_options.max_age = 0;
        const remove_value = try common.buildSetCookieHeader(self.allocator, name, "", remove_options);
        defer self.allocator.free(remove_value);
        try self.response.headers.append(HeaderName.SET_COOKIE, remove_value);
    }

    /// Sends a plain text response.
    pub fn text(self: *Self, data: []const u8) !Response {
        _ = try self.response.header(HeaderName.CONTENT_TYPE, "text/plain; charset=utf-8");
        _ = self.response.body(data);
        return self.response.build();
    }

    /// Sends an HTML response.
    pub fn html(self: *Self, data: []const u8) !Response {
        _ = try self.response.header(HeaderName.CONTENT_TYPE, "text/html; charset=utf-8");
        _ = self.response.body(data);
        return self.response.build();
    }

    /// Sends a file response.
    pub fn file(self: *Self, path: []const u8) !Response {
        // Reject path traversal: check for ".." segments in raw and
        // percent-decoded form. Also reject absolute paths and null bytes.
        if (containsTraversal(path)) {
            return self.status(403).text("Forbidden");
        }

        const f = std.fs.cwd().openFile(path, .{ .no_follow = true }) catch return self.status(404).text("Not Found");
        defer f.close();

        const stat = try f.stat();
        if (stat.size > self.max_file_size) {
            return self.status(413).text("File Too Large");
        }

        const content = try self.allocator.alloc(u8, @intCast(stat.size));
        defer self.allocator.free(content);
        _ = try f.readAll(content);

        _ = try self.response.header(HeaderName.CONTENT_TYPE, common.mimeTypeFromPath(path));
        _ = self.response.body(content);
        return self.response.build();
    }

    /// Sends chunked transfer-encoded payload with optional trailers.
    pub fn chunked(self: *Self, data: []const u8, trailers: ?*const Headers) !Response {
        const encoded = try http.encodeChunkedBody(data, trailers, self.allocator);
        defer self.allocator.free(encoded);

        _ = try self.response.header(HeaderName.TRANSFER_ENCODING, "chunked");
        if (trailers) |trailer_headers| {
            const trailer_names = try trailerHeaderNames(self.allocator, trailer_headers);
            defer self.allocator.free(trailer_names);
            _ = try self.response.header("Trailer", trailer_names);
        }
        _ = self.response.body(encoded);
        return self.response.build();
    }

    /// Sends one-shot Server-Sent Events payload.
    pub fn sse(self: *Self, events: []const SseEvent) !Response {
        var payload = std.ArrayListUnmanaged(u8).empty;
        defer payload.deinit(self.allocator);
        const writer = arrayListWriter(&payload, self.allocator);

        for (events) |evt| {
            if (evt.id) |id| try writer.print("id: {s}\n", .{id});
            if (evt.event) |name| try writer.print("event: {s}\n", .{name});
            if (evt.retry_ms) |retry_ms| try writer.print("retry: {d}\n", .{retry_ms});

            var lines = mem.splitScalar(u8, evt.data, '\n');
            while (lines.next()) |line| {
                try writer.print("data: {s}\n", .{line});
            }
            try writer.writeAll("\n");
        }

        _ = try self.response.header(HeaderName.CONTENT_TYPE, "text/event-stream; charset=utf-8");
        _ = try self.response.header(HeaderName.CACHE_CONTROL, "no-cache");
        _ = try self.response.header(HeaderName.CONNECTION, "keep-alive");
        _ = self.response.body(payload.items);
        return self.response.build();
    }

    /// Sends a JSON response.
    pub fn json(self: *Self, value: anytype) !Response {
        _ = try self.response.json(value);
        return self.response.build();
    }

    /// Sends a redirect response.
    pub fn redirect(self: *Self, url: []const u8, code: u16) !Response {
        _ = self.response.status(code);
        _ = try self.response.header(HeaderName.LOCATION, url);
        return self.response.build();
    }
};

/// Handler function type.
pub const Handler = *const fn (*Context) anyerror!Response;

/// HTTP Server.
pub const Server = struct {
    allocator: Allocator,
    io: Io,
    config: ServerConfig,
    router: Router,
    middleware: std.ArrayListUnmanaged(Middleware) = .empty,
    pre_route_hooks: std.ArrayListUnmanaged(PreRouteHook) = .empty,
    global_handler: ?Handler = null,
    listener: ?TcpListener = null,
    running: bool = false,
    connections: Io.Group = Io.Group.init,

    const Self = @This();

    /// Creates a server with default configuration.
    pub fn init(allocator: Allocator, io: Io) Self {
        return initWithConfig(allocator, io, .{});
    }

    /// Creates a server with custom configuration.
    pub fn initWithConfig(allocator: Allocator, io: Io, config: ServerConfig) Self {
        var cfg = config;
        if (cfg.max_connections == 0) cfg.max_connections = 1000;
        if (cfg.request_timeout_ms == 0) cfg.request_timeout_ms = 30_000;
        if (cfg.keep_alive_timeout_ms == 0) cfg.keep_alive_timeout_ms = 60_000;

        return .{
            .allocator = allocator,
            .io = io,
            .config = cfg,
            .router = Router.init(allocator),
        };
    }

    /// Releases all server resources.
    pub fn deinit(self: *Self) void {
        self.router.deinit();
        self.middleware.deinit(self.allocator);
        self.pre_route_hooks.deinit(self.allocator);
        if (self.listener) |*l| l.deinit();
    }

    /// Adds middleware to the server.
    pub fn use(self: *Self, mw: Middleware) !void {
        try self.middleware.append(self.allocator, mw);
    }

    /// Adds a pre-route hook executed before route matching.
    pub fn preRoute(self: *Self, hook: PreRouteHook) !void {
        try self.pre_route_hooks.append(self.allocator, hook);
    }

    /// Registers a global fallback handler for unmatched routes.
    pub fn global(self: *Self, handler: Handler) void {
        self.global_handler = handler;
    }

    /// Registers a route handler.
    pub fn route(self: *Self, method: types.Method, path: []const u8, handler: Handler) !void {
        try self.router.add(method, path, handler);
    }

    /// Registers a GET route.
    pub fn get(self: *Self, path: []const u8, handler: Handler) !void {
        try self.route(.GET, path, handler);
    }

    /// Registers a POST route.
    pub fn post(self: *Self, path: []const u8, handler: Handler) !void {
        try self.route(.POST, path, handler);
    }

    /// Registers a PUT route.
    pub fn put(self: *Self, path: []const u8, handler: Handler) !void {
        try self.route(.PUT, path, handler);
    }

    /// Registers a DELETE route.
    pub fn delete(self: *Self, path: []const u8, handler: Handler) !void {
        try self.route(.DELETE, path, handler);
    }

    /// Registers a PATCH route.
    pub fn patch(self: *Self, path: []const u8, handler: Handler) !void {
        try self.route(.PATCH, path, handler);
    }

    /// Registers a HEAD route.
    pub fn head(self: *Self, path: []const u8, handler: Handler) !void {
        try self.route(.HEAD, path, handler);
    }

    /// Registers an OPTIONS route.
    pub fn options(self: *Self, path: []const u8, handler: Handler) !void {
        try self.route(.OPTIONS, path, handler);
    }

    /// Registers a handler for all standard HTTP methods on a path.
    pub fn any(self: *Self, path: []const u8, handler: Handler) !void {
        try self.route(.GET, path, handler);
        try self.route(.POST, path, handler);
        try self.route(.PUT, path, handler);
        try self.route(.DELETE, path, handler);
        try self.route(.PATCH, path, handler);
        try self.route(.HEAD, path, handler);
        try self.route(.OPTIONS, path, handler);
        try self.route(.TRACE, path, handler);
        try self.route(.CONNECT, path, handler);
    }

    /// Starts the server and begins accepting connections.
    /// Uses Io.Group.concurrent to spawn a fiber per connection when
    /// the Io backend supports it (Kqueue on macOS, io_uring on Linux).
    /// Falls back to synchronous handling if concurrency is unavailable.
    pub fn listen(self: *Self) !void {
        const addr = try Address.parse(self.config.host, self.config.port);
        const backlog_u32: u32 = @max(self.config.max_connections, 1);
        const backlog: u31 = @intCast(@min(backlog_u32, @as(u32, std.math.maxInt(u31))));
        self.listener = try TcpListener.initWithOptions(addr, self.io, .{
            .kernel_backlog = backlog,
            .reuse_address = true,
        });
        self.running = true;

        std.debug.print("Server listening on {s}:{d}\n", .{ self.config.host, self.config.port });

        while (self.running) {
            const conn = self.listener.?.accept() catch |err| {
                std.debug.print("Accept error: {}\n", .{err});
                continue;
            };

            // Spawn a lightweight fiber to handle this connection concurrently.
            // If the Io backend doesn't support concurrency, fall back to sync.
            self.connections.concurrent(self.io, handleConnectionFiber, .{ self, conn.socket }) catch {
                self.handleConnection(conn.socket) catch |err| {
                    std.debug.print("Handler error: {}\n", .{err});
                };
            };
        }

        // Wait for all in-flight connections to finish before returning.
        self.connections.await(self.io) catch {};
    }

    /// Stops the server.
    pub fn stop(self: *Self) void {
        self.running = false;
        // Cancel all in-flight connection fibers.
        self.connections.cancel(self.io);
        if (self.listener) |*l| {
            l.deinit();
            self.listener = null;
        }
    }

    /// Fiber entry point for concurrent connection handling.
    /// Signature returns `Io.Cancelable!void` as required by Group.concurrent.
    fn handleConnectionFiber(self: *Self, socket: Socket) Io.Cancelable!void {
        self.handleConnection(socket) catch |err| {
            std.debug.print("Handler error: {}\n", .{err});
        };
    }

    /// Handles a single connection.
    fn handleConnection(self: *Self, socket: Socket) !void {
        var sock = socket;
        defer sock.close();

        var first_request = true;
        while (self.running) {
            const timeout_ms = if (first_request) self.config.request_timeout_ms else self.config.keep_alive_timeout_ms;
            if (timeout_ms > 0) {
                try sock.setRecvTimeout(timeout_ms);
            }

            var buffer: [8192]u8 = undefined;
            var parser = Parser.init(self.allocator);
            defer parser.deinit();
            parser.max_body_size = self.config.max_body_size;
            parser.max_headers = self.config.max_headers;

            // Wall-clock deadline prevents slow-loris attacks where an attacker
            // trickles bytes just fast enough to avoid per-recv timeouts.
            const deadline_ms: i64 = if (timeout_ms > 0) milliTimestamp() + @as(i64, @intCast(timeout_ms)) else 0;

            while (!parser.isComplete()) {
                if (deadline_ms > 0 and milliTimestamp() >= deadline_ms) {
                    try self.sendError(&sock, 408);
                    return;
                }
                const n = try sock.recv(&buffer);
                if (n == 0) return;
                _ = parser.feed(buffer[0..n]) catch |err| switch (err) {
                    error.BodyTooLarge => {
                        try self.sendError(&sock, 413);
                        return;
                    },
                    error.HeaderTooLarge, error.TooManyHeaders => {
                        try self.sendError(&sock, 431);
                        return;
                    },
                    error.InvalidHeader, error.InvalidChunkEncoding => {
                        try self.sendError(&sock, 400);
                        return;
                    },
                    else => return err,
                };
                if (parser.isError()) {
                    try self.sendError(&sock, 400);
                    return;
                }
            }

            var req = try Request.init(
                self.allocator,
                parser.method orelse .GET,
                parser.path orelse "/",
            );
            defer req.deinit();
            req.version = parser.version;

            for (parser.headers.entries.items) |h| {
                try req.headers.append(h.name, h.value);
            }

            if (parser.getBody().len > 0) {
                // Dupe the body so req owns its data independently of the parser,
                // which is stack-allocated and cleaned up via defer.
                req.body = try self.allocator.dupe(u8, parser.getBody());
                req.body_owned = true;
            }

            var ctx = Context.init(self.allocator, &req);
            ctx.max_file_size = self.config.max_file_size;
            defer ctx.deinit();

            for (self.pre_route_hooks.items) |hook| {
                hook(&ctx) catch |err| {
                    std.debug.print("Pre-route hook error: {}\n", .{err});
                    return self.sendError(&sock, 500);
                };
            }

            var suppress_body = false;
            var route_result = self.router.find(req.method, req.uri.path);

            // If HEAD is not explicitly registered, fall back to GET semantics
            // and suppress the response body.
            if (route_result == null and req.method == .HEAD) {
                route_result = self.router.find(.GET, req.uri.path);
                suppress_body = route_result != null;
            }

            if (route_result) |r| {
                for (r.params) |p| {
                    try ctx.params.put(p.name, p.value);
                }
            }

            var response: Response = undefined;
            if (route_result) |r| {
                response = self.executeMiddleware(&ctx, r.handler) catch |err| {
                    std.debug.print("Handler error: {}\n", .{err});
                    return self.sendError(&sock, 500);
                };
            } else {
                var allow_methods: [16]types.Method = undefined;
                const allow_count = self.router.allowedMethods(req.uri.path, &allow_methods);

                if (req.method == .OPTIONS and allow_count > 0) {
                    response = Response.init(self.allocator, 204);
                    try self.setAllowHeader(&response.headers, allow_methods[0..allow_count]);
                } else if (allow_count > 0) {
                    response = Response.init(self.allocator, 405);
                    try self.setAllowHeader(&response.headers, allow_methods[0..allow_count]);
                } else if (self.global_handler) |global_handler| {
                    response = self.executeMiddleware(&ctx, global_handler) catch |err| {
                        std.debug.print("Global handler error: {}\n", .{err});
                        return self.sendError(&sock, 500);
                    };
                } else {
                    return self.sendError(&sock, 404);
                }
            }

            defer response.deinit();

            if (suppress_body) {
                if (response.body_owned) {
                    if (response.body) |body| self.allocator.free(body);
                    response.body_owned = false;
                }
                response.body = null;
            }

            const request_wants_keep_alive = req.headers.isKeepAlive(req.version);
            const keep_alive = self.config.keep_alive and request_wants_keep_alive;
            if (!keep_alive) {
                try response.headers.set(HeaderName.CONNECTION, "close");
            }

            try self.ensureContentLengthHeader(&response);

            const formatted = try http.formatResponse(&response, self.allocator);
            defer self.allocator.free(formatted);

            try sock.sendAll(formatted);

            if (!keep_alive) return;
            first_request = false;
        }
    }

    /// Sends an error response.
    fn sendError(self: *Self, socket: *Socket, code: u16) !void {
        var resp = Response.init(self.allocator, code);
        defer resp.deinit();

        try self.ensureContentLengthHeader(&resp);

        const formatted = try http.formatResponse(&resp, self.allocator);
        defer self.allocator.free(formatted);

        try socket.sendAll(formatted);
    }

    fn ensureContentLengthHeader(self: *Self, response: *Response) !void {
        _ = self;
        if (response.headers.get(HeaderName.CONTENT_LENGTH) != null) return;
        if (response.headers.isChunked()) return;

        const body_len: usize = if (response.body) |b| b.len else 0;
        var len_buf: [32]u8 = undefined;
        const len_str = std.fmt.bufPrint(&len_buf, "{d}", .{body_len}) catch unreachable;
        try response.headers.set(HeaderName.CONTENT_LENGTH, len_str);
    }

    /// Sets the `Allow` header for automatic OPTIONS and 405 responses.
    fn setAllowHeader(self: *Self, headers: *Headers, methods: []const types.Method) !void {
        var allow = std.ArrayListUnmanaged(u8).empty;
        defer allow.deinit(self.allocator);
        const writer = arrayListWriter(&allow, self.allocator);

        var first = true;
        var has_options = false;

        for (methods) |m| {
            if (m == .OPTIONS) has_options = true;
            if (!first) try writer.writeAll(", ");
            first = false;
            try writer.writeAll(m.toString());
        }

        if (!has_options) {
            if (!first) try writer.writeAll(", ");
            try writer.writeAll("OPTIONS");
        }

        try headers.set("Allow", allow.items);
    }

    const MiddlewareExecState = struct {
        server: *Self,
        route_handler: Handler,
        index: usize = 0,
    };

    fn executeMiddleware(self: *Self, ctx: *Context, route_handler: Handler) !Response {
        var state = MiddlewareExecState{
            .server = self,
            .route_handler = route_handler,
        };
        try ctx.data.put("__mw_exec_state", @ptrCast(&state));
        defer _ = ctx.data.remove("__mw_exec_state");

        return middlewareNext(ctx);
    }

    fn middlewareNext(ctx: *Context) anyerror!Response {
        const raw = ctx.data.get("__mw_exec_state") orelse return error.MissingMiddlewareState;
        const state: *MiddlewareExecState = @ptrCast(@alignCast(raw));

        if (state.index < state.server.middleware.items.len) {
            const mw = state.server.middleware.items[state.index];
            state.index += 1;
            return mw.handler(ctx, middlewareNext);
        }

        return state.route_handler(ctx);
    }
};

/// Returns true if `path` contains traversal sequences (`..`), null bytes,
/// or starts with `/` (absolute). Checks both raw and common percent-encoded
/// variants (`%2e`, `%2E`).
fn containsTraversal(path: []const u8) bool {
    // Reject null bytes — can bypass C-based filesystem APIs.
    if (mem.indexOfScalar(u8, path, 0) != null) return true;
    // Reject absolute paths.
    if (path.len > 0 and path[0] == '/') return true;

    // Check for ".." in raw form.
    if (mem.indexOf(u8, path, "..") != null) return true;

    // Check for percent-encoded dot variants: %2e and %2E.
    var i: usize = 0;
    while (i < path.len) {
        if (isEncodedDot(path, i)) {
            // Check if followed by another dot (raw or encoded).
            const next = i + 3;
            if (next < path.len and path[next] == '.') return true;
            if (isEncodedDot(path, next)) return true;
            // Check if preceded by a raw dot.
            if (i > 0 and path[i - 1] == '.') return true;
        }
        i += 1;
    }
    return false;
}

fn isEncodedDot(path: []const u8, i: usize) bool {
    if (i + 2 >= path.len) return false;
    if (path[i] != '%') return false;
    if (path[i + 1] != '2') return false;
    return path[i + 2] == 'e' or path[i + 2] == 'E';
}

fn trailerHeaderNames(allocator: Allocator, headers: *const Headers) ![]u8 {
    var out = std.ArrayListUnmanaged(u8).empty;
    errdefer out.deinit(allocator);
    const writer = arrayListWriter(&out, allocator);

    var first = true;
    for (headers.entries.items) |h| {
        if (!first) try writer.writeAll(", ");
        first = false;
        try writer.writeAll(h.name);
    }

    return out.toOwnedSlice(allocator);
}

test "Server initialization" {
    const allocator = std.testing.allocator;
    var server = Server.init(allocator, std.testing.io);
    defer server.deinit();

    try std.testing.expectEqual(@as(u16, 8080), server.config.port);
}

test "Context response helpers" {
    const allocator = std.testing.allocator;
    var req = try Request.init(allocator, .GET, "/test");
    defer req.deinit();

    var ctx = Context.init(allocator, &req);
    defer ctx.deinit();

    _ = ctx.status(201);
    try std.testing.expectEqual(@as(u16, 201), ctx.response.status_code);
}

test "Server with config" {
    const allocator = std.testing.allocator;
    var server = Server.initWithConfig(allocator, std.testing.io, .{
        .host = "0.0.0.0",
        .port = 3000,
    });
    defer server.deinit();

    try std.testing.expectEqual(@as(u16, 3000), server.config.port);
    try std.testing.expectEqualStrings("0.0.0.0", server.config.host);
}

test "Context query parsing" {
    const allocator = std.testing.allocator;
    var req = try Request.init(allocator, .GET, "/search?q=zig&lang=en");
    defer req.deinit();

    var ctx = Context.init(allocator, &req);
    defer ctx.deinit();

    try std.testing.expectEqualStrings("zig", ctx.query("q").?);
    try std.testing.expectEqualStrings("en", ctx.query("lang").?);
    try std.testing.expect(ctx.query("missing") == null);
}

test "Context cookie helpers" {
    const allocator = std.testing.allocator;
    var req = try Request.init(allocator, .GET, "/");
    defer req.deinit();
    try req.headers.set(HeaderName.COOKIE, "session=abc123; theme=dark");

    var ctx = Context.init(allocator, &req);
    defer ctx.deinit();

    try std.testing.expectEqualStrings("abc123", ctx.cookie("session").?);
    try std.testing.expectEqualStrings("dark", ctx.cookie("theme").?);
    try std.testing.expect(ctx.cookie("missing") == null);

    try ctx.setCookie("session", "next", .{ .path = "/", .http_only = true, .same_site = .lax });
    const set_cookie = ctx.response.headers.get(HeaderName.SET_COOKIE).?;
    try std.testing.expect(mem.indexOf(u8, set_cookie, "session=next") != null);

    try ctx.removeCookie("session", .{ .path = "/" });
    const all_set_cookies = try ctx.response.headers.getAll(HeaderName.SET_COOKIE, allocator);
    defer allocator.free(all_set_cookies);
    try std.testing.expect(all_set_cookies.len >= 2);
}

test "Router allowed methods for path" {
    const allocator = std.testing.allocator;
    var server = Server.init(allocator, std.testing.io);
    defer server.deinit();

    const handler = struct {
        fn h(_: *Context) anyerror!Response {
            return error.TestUnexpectedResult;
        }
    }.h;

    try server.get("/users/:id", handler);
    try server.put("/users/:id", handler);
    try server.delete("/users/:id", handler);

    var methods: [16]types.Method = undefined;
    const count = server.router.allowedMethods("/users/42", &methods);

    try std.testing.expect(count >= 3);

    var has_get = false;
    var has_put = false;
    var has_delete = false;
    for (methods[0..count]) |m| {
        if (m == .GET) has_get = true;
        if (m == .PUT) has_put = true;
        if (m == .DELETE) has_delete = true;
    }

    try std.testing.expect(has_get);
    try std.testing.expect(has_put);
    try std.testing.expect(has_delete);
}

test "Server any() registers all methods" {
    const allocator = std.testing.allocator;
    var server = Server.init(allocator, std.testing.io);
    defer server.deinit();

    const handler = struct {
        fn h(_: *Context) anyerror!Response {
            return error.TestUnexpectedResult;
        }
    }.h;

    try server.any("/wild", handler);

    try std.testing.expect(server.router.find(.GET, "/wild") != null);
    try std.testing.expect(server.router.find(.POST, "/wild") != null);
    try std.testing.expect(server.router.find(.TRACE, "/wild") != null);
    try std.testing.expect(server.router.find(.CONNECT, "/wild") != null);
}

test "ServerConfig defaults" {
    const config = ServerConfig{};
    try std.testing.expectEqual(@as(usize, 10 * 1024 * 1024), config.max_body_size);
    try std.testing.expectEqual(@as(usize, 100), config.max_headers);
    try std.testing.expectEqual(@as(usize, 100 * 1024 * 1024), config.max_file_size);
}

test "Context max_file_size default and override" {
    const allocator = std.testing.allocator;
    var req = try Request.init(allocator, .GET, "/");
    defer req.deinit();

    var ctx = Context.init(allocator, &req);
    defer ctx.deinit();

    // Default should match ServerConfig default.
    try std.testing.expectEqual(@as(usize, 100 * 1024 * 1024), ctx.max_file_size);

    // Can be overridden (as server does in handleConnection).
    ctx.max_file_size = 1024;
    try std.testing.expectEqual(@as(usize, 1024), ctx.max_file_size);
}

test "Context file rejects path traversal" {
    const allocator = std.testing.allocator;
    var req = try Request.init(allocator, .GET, "/");
    defer req.deinit();

    var ctx = Context.init(allocator, &req);
    defer ctx.deinit();

    var response = try ctx.file("../etc/passwd");
    defer response.deinit();

    try std.testing.expectEqual(@as(u16, 403), response.status.code);
}

test "Parser max_headers is configurable" {
    const allocator = std.testing.allocator;
    var parser = Parser.init(allocator);
    defer parser.deinit();
    parser.max_headers = 2;

    // Feed a request with 3 headers — should trigger error state.
    _ = try parser.feed("GET / HTTP/1.1\r\nA: 1\r\nB: 2\r\nC: 3\r\n\r\n");
    try std.testing.expect(parser.isError());
}

test "Parser max_body_size is configurable" {
    const allocator = std.testing.allocator;
    var parser = Parser.init(allocator);
    defer parser.deinit();
    parser.max_body_size = 4;

    _ = try parser.feed("POST / HTTP/1.1\r\nContent-Length: 10\r\n\r\n");
    // Content-Length 10 > max_body_size 4, should be error state.
    try std.testing.expect(parser.isError());
}
