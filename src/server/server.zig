//! HTTP Server Implementation for httpx.zig
//!
//! Production-ready HTTP server with comprehensive features:
//!
//! - Pattern-based routing with path parameters
//! - Middleware stack support
//! - Context-based request handling
//! - JSON response helpers
//! - Static file serving
//! - HTTP/2 with two entry paths:
//!   1. **Prior knowledge** (RFC 7540 §3.4): client sends h2 preface directly;
//!      the server detects it from the first bytes of the connection.
//!   2. **h2c upgrade** (RFC 7540 §3.2): client sends an HTTP/1.1 request with
//!      `Upgrade: h2c`; the server responds with 101 and switches to h2.
//! - Cross-platform (Linux, Windows, macOS)
//!
//! ## TLS / HTTPS
//!
//! Zig 0.16 `std.crypto.tls` only provides a `Client` — there is no
//! server-side TLS implementation yet. For HTTPS, deploy behind a TLS-
//! terminating reverse proxy (e.g. nginx, Caddy, envoy) that forwards
//! plaintext HTTP/2 (h2c) or HTTP/1.1 to this server. The `tls_cert_path`
//! and `tls_key_path` fields in `ServerConfig` are reserved for future
//! direct TLS support.

const std = @import("std");
const arrayListWriter = @import("../util/array_list_writer.zig").arrayListWriter;
const mem = std.mem;
const Allocator = mem.Allocator;
const Io = std.Io;
const milliTimestamp = @import("../util/common.zig").milliTimestamp;

const types = @import("../core/types.zig");
const Request = @import("../core/request.zig").Request;
const Response = @import("../core/response.zig").Response;
const ResponseBuilder = @import("../core/response.zig").ResponseBuilder;
const Headers = @import("../core/headers.zig").Headers;
const HeaderName = @import("../core/headers.zig").HeaderName;
const containsCrLf = @import("../core/headers.zig").containsCrLf;
const Parser = @import("../protocol/parser.zig").Parser;
const http = @import("../protocol/http.zig");
const Socket = @import("../net/socket.zig").Socket;
const Address = @import("../net/socket.zig").Address;
const TcpListener = @import("../net/socket.zig").TcpListener;
const Router = @import("router.zig").Router;
const RouteParam = @import("router.zig").RouteParam;
const middleware_mod = @import("middleware.zig");
const Middleware = middleware_mod.Middleware;
const common = @import("../util/common.zig");
const h2_mod = @import("../protocol/h2_connection.zig");
const H2Connection = h2_mod.H2Connection;
const hpack = @import("../protocol/hpack.zig");

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
    max_file_size: usize = types.default_max_body_size,
    request_timeout_ms: u64 = 30_000,
    keep_alive_timeout_ms: u64 = 60_000,
    max_connections: u32 = 1000,
    keep_alive: bool = true,
    max_requests_per_connection: u32 = 1000,
    threads: u32 = 0,
    /// Reserved for future server-side TLS support. Zig 0.16 only provides
    /// `std.crypto.tls.Client`; there is no server TLS implementation yet.
    /// Use a TLS-terminating reverse proxy in the meantime.
    tls_cert_path: ?[]const u8 = null,
    tls_key_path: ?[]const u8 = null,
};

/// Request context passed to handlers.
pub const Context = struct {
    allocator: Allocator,
    io: Io,
    request: *Request,
    response: ResponseBuilder,
    params: []const RouteParam = &.{},
    data: ?std.StringHashMap(DataEntry) = null,
    max_file_size: usize = types.default_max_body_size,

    // H2 streaming fields (set by the server for H2 streams, null for HTTP/1.1).
    h2: ?*H2Connection = null,
    h2_sock: ?*Socket = null,
    h2_stream_id: u31 = 0,
    h2_stream_sent: bool = false,

    /// Entry in the context data map with an optional destructor for cleanup.
    pub const DataEntry = struct {
        ptr: *anyopaque,
        dtor: ?*const fn (*anyopaque) void = null,
    };

    const Self = @This();

    /// Creates a new context for a request.
    pub fn init(allocator: Allocator, io: Io, req: *Request) Self {
        return .{
            .allocator = allocator,
            .io = io,
            .request = req,
            .response = ResponseBuilder.init(allocator),
        };
    }

    /// Releases context resources. Calls destructors for data entries that have them.
    pub fn deinit(self: *Self) void {
        if (self.data) |*data| {
            var it = data.iterator();
            while (it.next()) |entry| {
                if (entry.value_ptr.dtor) |dtor| dtor(entry.value_ptr.ptr);
            }
            data.deinit();
        }
        self.response.deinit();
    }

    /// Stores a pointer in the context data map with an optional destructor.
    /// If replacing an existing entry, its destructor is called first.
    pub fn setData(self: *Self, key: []const u8, ptr: *anyopaque, dtor: ?*const fn (*anyopaque) void) !void {
        if (self.data == null) {
            self.data = std.StringHashMap(DataEntry).init(self.allocator);
        }
        if (self.data.?.get(key)) |existing| {
            if (existing.dtor) |d| d(existing.ptr);
        }
        try self.data.?.put(key, .{ .ptr = ptr, .dtor = dtor });
    }

    /// Retrieves a stored pointer by key.
    pub fn getData(self: *const Self, key: []const u8) ?*anyopaque {
        const data = self.data orelse return null;
        return if (data.get(key)) |entry| entry.ptr else null;
    }

    /// Returns a URL parameter by name.
    pub fn param(self: *const Self, name: []const u8) ?[]const u8 {
        for (self.params) |p| {
            if (std.mem.eql(u8, p.name, name)) return p.value;
        }
        return null;
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
    /// Returns error.HeaderContainsCrLf if the name or value contains CR or LF.
    pub fn setCookie(self: *Self, name: []const u8, value: []const u8, options: CookieOptions) !void {
        if (containsCrLf(name) or containsCrLf(value))
            return error.HeaderContainsCrLf;
        const set_cookie = try common.buildSetCookieHeader(self.allocator, name, value, options);
        try self.appendOwnedSetCookie(set_cookie);
    }

    /// Appends a Set-Cookie header that removes a cookie via Max-Age=0.
    /// Returns error.HeaderContainsCrLf if the name contains CR or LF.
    pub fn removeCookie(self: *Self, name: []const u8, options: CookieOptions) !void {
        if (containsCrLf(name))
            return error.HeaderContainsCrLf;
        var remove_options = options;
        remove_options.max_age = 0;
        const remove_value = try common.buildSetCookieHeader(self.allocator, name, "", remove_options);
        try self.appendOwnedSetCookie(remove_value);
    }

    /// Appends a Set-Cookie header with an already-allocated value.
    /// On error the value is freed.
    fn appendOwnedSetCookie(self: *Self, value: []u8) !void {
        errdefer self.allocator.free(value);
        // Validate the fully-composed value (covers options.path, .domain, etc.)
        if (containsCrLf(value)) return error.HeaderContainsCrLf;
        const owned_name = try self.allocator.dupe(u8, HeaderName.SET_COOKIE);
        errdefer self.allocator.free(owned_name);
        try self.response.headers.entries.append(self.allocator, .{
            .name = owned_name,
            .value = value,
            .owned = true,
        });
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

        const f = Io.Dir.cwd().openFile(self.io, path, .{}) catch return self.status(404).text("Not Found");
        defer f.close(self.io);

        const stat = f.stat(self.io) catch return self.status(404).text("Not Found");
        if (stat.size > self.max_file_size) {
            return self.status(413).text("File Too Large");
        }

        const content = try self.allocator.alloc(u8, @intCast(stat.size));
        errdefer self.allocator.free(content);
        _ = f.readPositionalAll(self.io, content, 0) catch return self.status(500).text("Read Error");

        _ = try self.response.header(HeaderName.CONTENT_TYPE, common.mimeTypeFromPath(path));
        self.response.body_data = content;
        self.response.body_owned = true;
        return self.response.build();
    }

    /// Sends chunked transfer-encoded payload with optional trailers.
    pub fn chunked(self: *Self, data: []const u8, trailers: ?*const Headers) !Response {
        const encoded = try http.encodeChunkedBody(data, trailers, self.allocator);
        errdefer self.allocator.free(encoded);

        _ = try self.response.header(HeaderName.TRANSFER_ENCODING, "chunked");
        if (trailers) |trailer_headers| {
            const trailer_names = try trailerHeaderNames(self.allocator, trailer_headers);
            defer self.allocator.free(trailer_names);
            _ = try self.response.header(HeaderName.TRAILER, trailer_names);
        }
        // Transfer ownership to the builder to avoid a second allocation in build().
        self.response.body_data = encoded;
        self.response.body_owned = true;
        return self.response.build();
    }

    /// Sends one-shot Server-Sent Events payload.
    pub fn sse(self: *Self, events: []const SseEvent) !Response {
        var payload = std.ArrayListUnmanaged(u8).empty;
        defer payload.deinit(self.allocator);
        const writer = arrayListWriter(&payload, self.allocator);

        for (events) |evt| {
            if (evt.id) |id| {
                if (mem.indexOfAny(u8, id, "\r\n") != null) return error.InvalidSseField;
                try writer.print("id: {s}\n", .{id});
            }
            if (evt.event) |name| {
                if (mem.indexOfAny(u8, name, "\r\n") != null) return error.InvalidSseField;
                try writer.print("event: {s}\n", .{name});
            }
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

    /// Writer for server-side HTTP/2 streaming responses.
    /// Acquired via `ctx.streamH2()`. Each `write()` sends DATA frame(s)
    /// without END_STREAM. Call `close()` to send END_STREAM.
    pub const H2StreamWriter = struct {
        h2: *H2Connection,
        sock: *Socket,
        stream_id: u31,
        io: Io,
        closed: bool = false,

        /// Sends data as DATA frames without END_STREAM.
        pub fn write(self: *H2StreamWriter, data: []const u8) !void {
            if (self.closed) return error.StreamClosed;
            self.h2.write_mutex.lockUncancelable(self.io);
            defer self.h2.write_mutex.unlock(self.io);
            try self.h2.writeData(self.sock, self.stream_id, data, false);
        }

        /// Sends END_STREAM and marks the writer done.
        pub fn close(self: *H2StreamWriter) !void {
            if (self.closed) return;
            self.closed = true;
            self.h2.write_mutex.lockUncancelable(self.io);
            defer self.h2.write_mutex.unlock(self.io);
            try self.h2.writeData(self.sock, self.stream_id, &.{}, true);
        }
    };

    /// Sends HEADERS (without END_STREAM) and returns a writer for incremental
    /// DATA frames. The handler must call `writer.close()` when done.
    /// Only available for HTTP/2 streams.
    pub fn streamH2(self: *Self, status_code: u16, extra_headers: []const hpack.HeaderEntry) !H2StreamWriter {
        const h2 = self.h2 orelse return error.NotH2;
        const sock = self.h2_sock orelse return error.NotH2;

        var status_buf: [3]u8 = undefined;
        const h2_headers = try H2Connection.buildResponseHeaders(
            status_code, extra_headers, &status_buf, self.allocator,
        );
        defer self.allocator.free(h2_headers);

        h2.write_mutex.lockUncancelable(self.io);
        defer h2.write_mutex.unlock(self.io);
        try h2.sendHeaders(sock, self.h2_stream_id, h2_headers, false);

        self.h2_stream_sent = true;
        return .{ .h2 = h2, .sock = sock, .stream_id = self.h2_stream_id, .io = self.io };
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
    conn_semaphore: Io.Semaphore,

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
            .conn_semaphore = .{ .permits = cfg.max_connections },
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
            // Block accept loop when at max concurrent connections.
            // Gate before accept so we don't hold open sockets while waiting.
            self.conn_semaphore.waitUncancelable(self.io);

            const conn = self.listener.?.accept() catch |err| {
                self.conn_semaphore.post(self.io);
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

    /// Stops the server immediately, cancelling all in-flight connections.
    pub fn stop(self: *Self) void {
        self.running = false;
        self.connections.cancel(self.io);
        if (self.listener) |*l| {
            l.deinit();
            self.listener = null;
        }
    }

    /// Gracefully shuts down the server: stops accepting new connections and
    /// waits up to `timeout_ms` for in-flight requests to complete before
    /// forcefully cancelling them. Similar to Go's http.Server.Shutdown.
    pub fn shutdown(self: *Self, timeout_ms: u64) void {
        self.running = false;
        if (self.listener) |*l| {
            l.deinit();
            self.listener = null;
        }
        // Give in-flight connections time to finish.
        if (timeout_ms > 0) {
            self.io.sleep(Io.Duration.fromMilliseconds(@intCast(timeout_ms)), .monotonic) catch {};
        }
        // Force-cancel any remaining connections.
        self.connections.cancel(self.io);
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
        defer self.conn_semaphore.post(self.io);
        var sock = socket;
        defer sock.close();

        // Set initial timeout once; only update when transitioning to keep-alive.
        if (self.config.request_timeout_ms > 0) {
            try sock.setRecvTimeout(self.config.request_timeout_ms);
            try sock.setSendTimeout(self.config.request_timeout_ms);
        }

        // Peek at the first bytes to detect HTTP/2 "prior knowledge" (RFC 7540 §3.4).
        // The h2 preface is "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" (24 bytes).
        var peek_buf: [8192]u8 = undefined;
        const first_n = try sock.recv(&peek_buf);
        if (first_n == 0) return;

        if (first_n >= 24 and mem.eql(u8, peek_buf[0..24], http.HTTP2_PREFACE)) {
            return self.handleH2Connection(&sock, peek_buf[24..first_n]);
        }

        // HTTP/1.1 path — feed the already-read bytes to the parser.
        var parser = Parser.init(self.allocator);
        defer parser.deinit();
        parser.max_body_size = self.config.max_body_size;
        parser.max_headers = self.config.max_headers;

        var first_request = true;
        var request_count: u32 = 0;
        var first_recv_done = true; // We already did the first recv.
        while (self.running) {

            var buffer: [8192]u8 = undefined;
            parser.reset();

            // Wall-clock deadline prevents slow-loris attacks where an attacker
            // trickles bytes just fast enough to avoid per-recv timeouts.
            const active_timeout = if (first_request) self.config.request_timeout_ms else self.config.keep_alive_timeout_ms;
            const deadline_ms: i64 = if (active_timeout > 0) milliTimestamp(self.io) + @as(i64, @intCast(active_timeout)) else 0;

            while (!parser.isComplete()) {
                if (deadline_ms > 0 and milliTimestamp(self.io) >= deadline_ms) {
                    try self.sendError(&sock, 408);
                    return;
                }
                // On the very first iteration, feed the bytes we already read
                // during protocol detection instead of doing another recv.
                const n = if (first_recv_done) blk: {
                    @memcpy(buffer[0..first_n], peek_buf[0..first_n]);
                    first_recv_done = false;
                    break :blk first_n;
                } else try sock.recv(&buffer);
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

            // Borrow headers and body from the parser without copying.
            // The parser outlives the request within this loop iteration:
            // req is deinitialized via `defer req.deinit()` before
            // `parser.reset()` at the top of the next iteration.
            for (parser.headers.iterator()) |h| {
                try req.headers.appendBorrowed(h.name, h.value);
            }

            if (parser.getBody().len > 0) {
                req.body = parser.getBody();
                req.body_owned = false;
            }

            // RFC 7231 §5.1.1: Respond to Expect: 100-continue so the
            // client knows it's safe to send the body.
            if (req.headers.get(HeaderName.EXPECT)) |expect| {
                if (std.ascii.eqlIgnoreCase(expect, "100-continue")) {
                    try sock.sendAll("HTTP/1.1 100 Continue\r\n\r\n");
                }
            }

            // RFC 7540 §3.2: h2c upgrade — switch to HTTP/2 over cleartext.
            if (first_request and http.isH2cUpgradeRequest(&req.headers)) {
                return self.handleH2cUpgrade(&sock, &req);
            }

            var ctx = Context.init(self.allocator, self.io, &req);
            ctx.max_file_size = self.config.max_file_size;
            defer ctx.deinit();

            for (self.pre_route_hooks.items) |hook| {
                hook(&ctx) catch |err| {
                    std.debug.print("Pre-route hook error: {}\n", .{err});
                    return self.sendError(&sock, 500);
                };
            }

            var suppress_body = false;
            var params_buf: [16]RouteParam = undefined;
            var route_result = self.router.find(req.method, req.uri.path, &params_buf);

            // If HEAD is not explicitly registered, fall back to GET semantics
            // and suppress the response body.
            if (route_result == null and req.method == .HEAD) {
                route_result = self.router.find(.GET, req.uri.path, &params_buf);
                suppress_body = route_result != null;
            }

            if (route_result) |r| {
                ctx.params = r.params;
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

            try ensureContentLengthHeader(&response);
            try ensureDateHeader(self.io, &response);

            try sendBuffered(&sock, &response);

            if (!keep_alive) return;

            // Drain any unread request body before reusing the connection
            // for the next request, similar to Go's net/http finishRequest.
            if (parser.content_length) |cl| {
                const body_read = parser.getBody().len;
                var remaining: u64 = if (cl > body_read) cl - body_read else 0;
                const max_drain: u64 = 256 * 1024; // Match Go's 256 KB limit.
                if (remaining > max_drain) return; // Too much to drain; close.
                var drain_buf: [8192]u8 = undefined;
                while (remaining > 0) {
                    const to_read = @min(remaining, drain_buf.len);
                    const n = sock.recv(drain_buf[0..@intCast(to_read)]) catch return;
                    if (n == 0) return;
                    remaining -= n;
                }
            }

            request_count += 1;
            if (request_count >= self.config.max_requests_per_connection) return;

            if (first_request) {
                first_request = false;
                // Transition to keep-alive timeout (only one setsockopt call).
                if (self.config.keep_alive_timeout_ms != self.config.request_timeout_ms and
                    self.config.keep_alive_timeout_ms > 0)
                {
                    try sock.setRecvTimeout(self.config.keep_alive_timeout_ms);
                }
            }
        }
    }

    /// Handles an HTTP/1.1 → HTTP/2 upgrade (h2c, RFC 7540 §3.2).
    /// Sends 101 Switching Protocols, handles the original request as stream 1,
    /// then enters the normal H2 receive loop for subsequent requests.
    fn handleH2cUpgrade(self: *Self, sock: *Socket, original_req: *Request) !void {
        // 1. Send 101 Switching Protocols.
        try sock.sendAll("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n");

        // 2. Decode the HTTP2-Settings header (base64url → SETTINGS payload).
        const settings_b64 = original_req.headers.get(HeaderName.HTTP2_SETTINGS) orelse
            return error.MissingH2cSettings;
        const settings_payload = try http.decodeH2cSettings(settings_b64, self.allocator);
        defer self.allocator.free(settings_payload);

        // 3. Create H2 connection and apply peer settings.
        var h2 = H2Connection.initServer(self.allocator, self.io);
        defer h2.deinit();
        try http.applySettingsPayload(&h2.peer_settings, settings_payload);

        // 4. Send server SETTINGS.
        try h2.sendSettings(sock);

        // 5. Handle the original HTTP/1.1 request as stream 1.
        _ = try h2.stream_manager.getOrCreateStream(1);
        original_req.version = .HTTP_2;
        try self.routeAndRespondH2(&h2, sock, 1, original_req);
        h2.stream_manager.removeStream(1);

        // 6. Enter the normal H2 receive loop for subsequent requests.
        // The client will next send the h2 preface (24 bytes) + SETTINGS.
        // Read and validate the preface.
        var preface_buf: [24]u8 = undefined;
        var preface_pos: usize = 0;
        while (preface_pos < 24) {
            const n = try sock.recv(preface_buf[preface_pos..]);
            if (n == 0) return;
            preface_pos += n;
        }
        if (!mem.eql(u8, &preface_buf, http.HTTP2_PREFACE)) return error.ProtocolError;

        // Read client's SETTINGS frame.
        var settings_frame = try h2.readFrame(sock);
        defer settings_frame.deinit(self.allocator);
        if (settings_frame.header.frame_type != .settings) return error.ProtocolError;
        try h2.handleSettings(&settings_frame, sock);

        // Run the standard H2 frame loop.
        var stream_fibers = Io.Group.init;
        defer {
            stream_fibers.await(self.io) catch {};
            if (!h2.goaway_sent) h2.sendGoaway(sock, .no_error) catch {};
        }

        while (!h2.goaway_received and self.running) {
            const maybe_sid = h2.processOneFrameLocked(sock, sock) catch |err| switch (err) {
                error.ConnectionClosed => break,
                else => return err,
            };

            const sid = maybe_sid orelse continue;
            const stream = h2.stream_manager.getStream(sid) orelse continue;
            if (!stream.completed) continue;
            if (stream.stream_error != null) {
                h2.stream_manager.removeStream(sid);
                continue;
            }

            stream_fibers.concurrent(self.io, handleH2StreamFiber, .{ self, &h2, sock, sid }) catch {
                self.handleH2Stream(&h2, sock, sid) catch |err| {
                    std.debug.print("H2 stream handler error: {}\n", .{err});
                };
            };
        }
    }

    /// Handles an HTTP/2 connection after the 24-byte preface has been consumed.
    /// `initial_data` contains any bytes read beyond the preface from the first recv.
    ///
    /// Runs a receive loop that reads frames and delivers them to per-stream
    /// mailboxes. When a stream is complete, a handler fiber is spawned to
    /// process the request concurrently (falls back to synchronous if the Io
    /// backend doesn't support concurrency).
    fn handleH2Connection(self: *Self, sock: *Socket, initial_data: []const u8) !void {
        var h2 = H2Connection.initServer(self.allocator, self.io);
        defer h2.deinit();

        // Wrap socket in a reader that first yields `initial_data`, then reads from socket.
        var h2_reader = H2SocketReader{ .socket = sock, .initial = initial_data, .initial_pos = 0 };

        // Read the client's SETTINGS frame (follows the preface).
        var settings_frame = try h2.readFrame(&h2_reader);
        defer settings_frame.deinit(self.allocator);
        if (settings_frame.header.frame_type != .settings) return error.ProtocolError;
        try h2.handleSettings(&settings_frame, sock);

        // Send our SETTINGS.
        try h2.sendSettings(sock);

        // Per-stream handler fibers. Awaited before h2 is deinitialized.
        var stream_fibers = Io.Group.init;
        defer {
            // Wait for all in-flight handler fibers to finish.
            stream_fibers.await(self.io) catch {};
            // Send GOAWAY with no_error if we haven't already, so the peer
            // can distinguish a clean close from a truncation.
            if (!h2.goaway_sent) {
                h2.sendGoaway(sock, .no_error) catch {};
            }
        }

        // Receive loop: reads frames, handles connection-level traffic, and
        // delivers stream-level frames to per-stream mailboxes. Uses the
        // locked variant so SETTINGS ACK / PING / WINDOW_UPDATE writes are
        // serialized with handler fibers' response writes.
        while (!h2.goaway_received and self.running) {
            const maybe_sid = h2.processOneFrameLocked(&h2_reader, sock) catch |err| switch (err) {
                error.ConnectionClosed => break,
                else => return err,
            };

            const sid = maybe_sid orelse continue;
            const stream = h2.stream_manager.getStream(sid) orelse continue;
            if (!stream.completed) continue;

            if (stream.stream_error != null) {
                h2.stream_manager.removeStream(sid);
                continue;
            }

            // Spawn a fiber to handle this stream's request. Falls back to
            // synchronous handling if the Io backend doesn't support fibers.
            stream_fibers.concurrent(self.io, handleH2StreamFiber, .{ self, &h2, sock, sid }) catch {
                self.handleH2Stream(&h2, sock, sid) catch |err| {
                    std.debug.print("H2 stream handler error: {}\n", .{err});
                };
            };
        }
    }

    /// Fiber entry point for per-stream HTTP/2 request handling.
    fn handleH2StreamFiber(self: *Self, h2: *H2Connection, sock: *Socket, stream_id: u31) Io.Cancelable!void {
        self.handleH2Stream(h2, sock, stream_id) catch |err| {
            std.debug.print("H2 stream handler error: {}\n", .{err});
        };
    }

    /// Handles a single completed HTTP/2 stream: decodes headers from the
    /// mailbox, routes the request, and sends the response. Acquires
    /// `h2.write_mutex` for the response write phase.
    fn handleH2Stream(self: *Self, h2: *H2Connection, sock: *Socket, stream_id: u31) !void {
        const stream = h2.stream_manager.getStream(stream_id) orelse return;

        const hp = stream.headers_payload orelse return;

        const decoded = try h2.decodeFrameHeaders(hp, stream.headers_flags);
        defer {
            for (decoded.headers) |*dh| {
                self.allocator.free(dh.name);
                self.allocator.free(dh.value);
            }
            self.allocator.free(decoded.headers);
        }

        // Extract pseudo-headers → build a Request.
        var method_str: ?[]const u8 = null;
        var path: ?[]const u8 = null;
        var authority: ?[]const u8 = null;

        var extra_headers = Headers.init(self.allocator);
        defer extra_headers.deinit();

        for (decoded.headers) |h| {
            if (mem.eql(u8, h.name, ":method")) {
                method_str = h.value;
            } else if (mem.eql(u8, h.name, ":path")) {
                path = h.value;
            } else if (mem.eql(u8, h.name, ":authority")) {
                authority = h.value;
            } else if (mem.eql(u8, h.name, ":scheme")) {
                // Consumed but not needed for routing.
            } else if (h.name.len > 0 and h.name[0] != ':') {
                try extra_headers.append(h.name, h.value);
            }
        }

        const req_method = types.Method.fromString(method_str orelse "GET") orelse .GET;
        var req = try Request.init(self.allocator, req_method, path orelse "/");
        defer req.deinit();
        req.version = .HTTP_2;

        for (extra_headers.entries.items) |entry| {
            try req.headers.appendBorrowed(entry.name, entry.value);
        }
        if (authority) |auth| {
            try req.headers.appendBorrowed("host", auth);
        }

        if (stream.data_buf.items.len > 0) {
            req.body = stream.data_buf.items;
            req.body_owned = false;
        }

        try self.routeAndRespondH2(h2, sock, stream_id, &req);
    }

    /// Routes a request through middleware and sends the H2 response.
    /// Shared between normal H2 streams (from HPACK) and h2c upgrade (from HTTP/1.1).
    fn routeAndRespondH2(self: *Self, h2: *H2Connection, sock: *Socket, stream_id: u31, req: *Request) !void {
        var ctx = Context.init(self.allocator, self.io, req);
        ctx.max_file_size = self.config.max_file_size;
        ctx.h2 = h2;
        ctx.h2_sock = sock;
        ctx.h2_stream_id = stream_id;
        defer ctx.deinit();

        for (self.pre_route_hooks.items) |hook| {
            hook(&ctx) catch {
                try self.sendH2ErrorLocked(h2, sock, stream_id, 500);
                return;
            };
        }

        var suppress_body = false;
        var params_buf: [16]RouteParam = undefined;
        var route_result = self.router.find(req.method, req.uri.path, &params_buf);

        if (route_result == null and req.method == .HEAD) {
            route_result = self.router.find(.GET, req.uri.path, &params_buf);
            suppress_body = route_result != null;
        }

        if (route_result) |r| {
            ctx.params = r.params;
        }

        var response: Response = undefined;
        if (route_result) |r| {
            response = self.executeMiddleware(&ctx, r.handler) catch {
                if (!ctx.h2_stream_sent) try self.sendH2ErrorLocked(h2, sock, stream_id, 500);
                return;
            };
        } else {
            response = Response.init(self.allocator, 404);
        }

        // If the handler used streamH2(), it already sent HEADERS+DATA.
        if (ctx.h2_stream_sent) {
            response.deinit();
            return;
        }
        defer response.deinit();

        if (suppress_body) {
            if (response.body_owned) {
                if (response.body) |b| self.allocator.free(b);
                response.body_owned = false;
            }
            response.body = null;
        }

        // Build response headers outside the lock.
        var resp_extra = std.ArrayListUnmanaged(hpack.HeaderEntry).empty;
        defer resp_extra.deinit(self.allocator);

        for (response.headers.entries.items) |entry| {
            try resp_extra.append(self.allocator, .{ .name = entry.name, .value = entry.value });
        }

        var status_buf: [3]u8 = undefined;
        const h2_headers = try H2Connection.buildResponseHeaders(
            response.status.code,
            resp_extra.items,
            &status_buf,
            self.allocator,
        );
        defer self.allocator.free(h2_headers);

        const has_body = response.body != null and response.body.?.len > 0;

        // Acquire write mutex for HPACK encoding + frame serialization.
        h2.write_mutex.lockUncancelable(h2.io);
        defer h2.write_mutex.unlock(h2.io);

        try h2.sendHeaders(sock, stream_id, h2_headers, !has_body);

        if (has_body) {
            try h2.writeData(sock, stream_id, response.body.?, true);
        }
    }

    /// Sends an HTTP/2 error response (just a HEADERS frame with :status).
    fn sendH2Error(self: *Self, h2: *H2Connection, writer: anytype, stream_id: u31, code: u16) !void {
        var status_buf: [3]u8 = undefined;
        const h2_headers = try H2Connection.buildResponseHeaders(code, &.{}, &status_buf, self.allocator);
        defer self.allocator.free(h2_headers);
        try h2.sendHeaders(writer, stream_id, h2_headers, true);
    }

    /// Like `sendH2Error` but acquires the write mutex first.
    fn sendH2ErrorLocked(self: *Self, h2: *H2Connection, writer: anytype, stream_id: u31, code: u16) !void {
        h2.write_mutex.lockUncancelable(h2.io);
        defer h2.write_mutex.unlock(h2.io);
        try self.sendH2Error(h2, writer, stream_id, code);
    }

    /// Sends an error response.
    fn sendError(self: *Self, socket: *Socket, code: u16) !void {
        var resp = Response.init(self.allocator, code);
        defer resp.deinit();

        try ensureContentLengthHeader(&resp);
        try ensureDateHeader(self.io, &resp);

        try sendBuffered(socket, &resp);
    }

    /// Serializes a response through a buffered writer to reduce syscalls.
    fn sendBuffered(socket: *Socket, resp: *Response) !void {
        try resp.serialize(socket.writer());
    }

    /// RFC 7231 §7.1.1.2: Origin servers MUST send a Date header field
    /// in IMF-fixdate format: e.g. "Sun, 06 Nov 1994 08:49:37 GMT".
    fn ensureDateHeader(io: Io, response: *Response) !void {
        if (response.headers.get(HeaderName.DATE) != null) return;
        const epoch = std.time.epoch;
        const now = Io.Clock.real.now(io);
        const ts: u64 = @intCast(@max(@divFloor(now.nanoseconds, std.time.ns_per_s), 0));
        const es = epoch.EpochSeconds{ .secs = ts };
        const day_secs = es.getDaySeconds();
        const epoch_day = es.getEpochDay();
        const year_day = epoch_day.calculateYearDay();
        const month_day = year_day.calculateMonthDay();

        // Day of week: 1970-01-01 was Thursday (index 4).
        const dow_names = [7][]const u8{ "Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed" };
        const mon_names = [12][]const u8{ "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };
        const dow = dow_names[epoch_day.day % 7];
        const mon = mon_names[month_day.month.numeric() - 1];

        var buf: [30]u8 = undefined;
        const date_str = std.fmt.bufPrint(&buf, "{s}, {d:0>2} {s} {d} {d:0>2}:{d:0>2}:{d:0>2} GMT", .{
            dow,
            month_day.day_index + 1,
            mon,
            year_day.year,
            day_secs.getHoursIntoDay(),
            day_secs.getMinutesIntoHour(),
            day_secs.getSecondsIntoMinute(),
        }) catch return;
        try response.headers.set("Date", date_str);
    }

    fn ensureContentLengthHeader(response: *Response) !void {
        if (response.headers.get(HeaderName.CONTENT_LENGTH) != null) return;
        if (response.headers.isChunked()) return;

        const body_len: usize = if (response.body) |b| b.len else 0;
        try response.headers.setContentLength(body_len);
    }

    /// Sets the `Allow` header for automatic OPTIONS and 405 responses.
    fn setAllowHeader(_: *Self, headers: *Headers, methods: []const types.Method) !void {
        var buf: [256]u8 = undefined;
        var pos: usize = 0;
        var has_options = false;

        for (methods) |m| {
            if (m == .OPTIONS) has_options = true;
            const name = m.toString();
            if (pos + name.len + 2 > buf.len) break;
            if (pos > 0) {
                @memcpy(buf[pos..][0..2], ", ");
                pos += 2;
            }
            @memcpy(buf[pos..][0..name.len], name);
            pos += name.len;
        }

        if (!has_options) {
            const opt = "OPTIONS";
            if (pos + opt.len + 2 <= buf.len) {
                if (pos > 0) {
                    @memcpy(buf[pos..][0..2], ", ");
                    pos += 2;
                }
                @memcpy(buf[pos..][0..opt.len], opt);
                pos += opt.len;
            }
        }

        try headers.set(HeaderName.ALLOW, buf[0..pos]);
    }

    /// Middleware execution state kept on the stack frame of executeMiddleware.
    /// Uses `@fieldParentPtr` through the embedded `Next` to carry state
    /// without exposing internal fields on Context.
    const MiddlewareExecState = struct {
        server: *Self,
        route_handler: Handler,
        index: usize = 0,
        next: middleware_mod.Next = .{ ._call = trampoline },

        fn trampoline(next_ptr: *middleware_mod.Next, ctx: *Context) anyerror!Response {
            const state: *MiddlewareExecState = @fieldParentPtr("next", next_ptr);
            return advance(ctx, state);
        }

        fn advance(ctx: *Context, state: *MiddlewareExecState) anyerror!Response {
            if (state.index < state.server.middleware.items.len) {
                const mw = state.server.middleware.items[state.index];
                state.index += 1;
                return mw.handler(ctx, &state.next);
            }
            return state.route_handler(ctx);
        }
    };

    fn executeMiddleware(self: *Self, ctx: *Context, route_handler: Handler) !Response {
        var state = MiddlewareExecState{
            .server = self,
            .route_handler = route_handler,
        };
        return MiddlewareExecState.advance(ctx, &state);
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
    // Reject backslashes — Windows path separators can bypass unix-only checks.
    if (mem.indexOfScalar(u8, path, '\\') != null) return true;

    // Check for ".." in raw form.
    if (mem.indexOf(u8, path, "..") != null) return true;

    // Check for percent-encoded slash (%2f, %2F) — can bypass directory checks.
    {
        var j: usize = 0;
        while (j + 2 < path.len) : (j += 1) {
            if (path[j] == '%' and path[j + 1] == '2' and (path[j + 2] == 'f' or path[j + 2] == 'F')) return true;
        }
    }

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

/// Duck-typed reader for h2 connection handling: yields `initial` bytes first,
/// then reads from the underlying socket via `recv`.
const H2SocketReader = struct {
    socket: *Socket,
    initial: []const u8,
    initial_pos: usize,

    pub fn read(self: *H2SocketReader, buf: []u8) !usize {
        if (self.initial_pos < self.initial.len) {
            const avail = self.initial.len - self.initial_pos;
            const n = @min(avail, buf.len);
            @memcpy(buf[0..n], self.initial[self.initial_pos .. self.initial_pos + n]);
            self.initial_pos += n;
            return n;
        }
        return self.socket.recv(buf);
    }
};

fn trailerHeaderNames(allocator: Allocator, headers: *const Headers) ![]u8 {
    const items = headers.iterator();
    const names = try allocator.alloc([]const u8, items.len);
    defer allocator.free(names);
    for (items, 0..) |h, i| names[i] = h.name;
    return std.mem.join(allocator, ", ", names);
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

    var ctx = Context.init(allocator, std.testing.io, &req);
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

    var ctx = Context.init(allocator, std.testing.io, &req);
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

    var ctx = Context.init(allocator, std.testing.io, &req);
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

    var pbuf: [16]RouteParam = undefined;
    try std.testing.expect(server.router.find(.GET, "/wild", &pbuf) != null);
    try std.testing.expect(server.router.find(.POST, "/wild", &pbuf) != null);
    try std.testing.expect(server.router.find(.TRACE, "/wild", &pbuf) != null);
    try std.testing.expect(server.router.find(.CONNECT, "/wild", &pbuf) != null);
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

    var ctx = Context.init(allocator, std.testing.io, &req);
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

    var ctx = Context.init(allocator, std.testing.io, &req);
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

    // Feed a request with 3 headers — should trigger TooManyHeaders error.
    const result = parser.feed("GET / HTTP/1.1\r\nA: 1\r\nB: 2\r\nC: 3\r\n\r\n");
    try std.testing.expectError(error.TooManyHeaders, result);
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

test "Context.streamH2 returns NotH2 for HTTP/1.1 context" {
    const allocator = std.testing.allocator;
    var req = try Request.init(allocator, .GET, "/");
    defer req.deinit();

    var ctx = Context.init(allocator, std.testing.io, &req);
    defer ctx.deinit();

    // h2 fields are null by default (HTTP/1.1 context).
    try std.testing.expectError(error.NotH2, ctx.streamH2(200, &.{}));
}

test "H2StreamWriter write and close" {
    const allocator = std.testing.allocator;

    var h2 = H2Connection.initServer(allocator, std.testing.io);
    defer h2.deinit();

    // Create a stream so writeData can find it.
    _ = try h2.stream_manager.getOrCreateStream(1);

    // Write to an in-memory buffer via a TestWriter.
    var buf = std.ArrayListUnmanaged(u8).empty;
    defer buf.deinit(allocator);
    const TestWriter = struct {
        list: *std.ArrayListUnmanaged(u8),
        alloc: Allocator,
        pub fn writeAll(self: @This(), data: []const u8) !void {
            try self.list.appendSlice(self.alloc, data);
        }
    };
    var sock_stub = TestWriter{ .list = &buf, .alloc = allocator };

    // Cast the stub to a Socket pointer isn't feasible, so test the
    // underlying H2Connection.writeData directly (what H2StreamWriter calls).
    // Send DATA without END_STREAM.
    try h2.writeData(&sock_stub, 1, "chunk1", false);
    const first_len = buf.items.len;
    try std.testing.expect(first_len > 6); // 9-byte frame header + "chunk1"

    try h2.writeData(&sock_stub, 1, "chunk2", false);
    try std.testing.expect(buf.items.len > first_len);

    // Send END_STREAM.
    try h2.writeData(&sock_stub, 1, &.{}, true);

    // Verify last frame has END_STREAM flag. The frame header is 9 bytes;
    // the last frame is an empty DATA frame with END_STREAM.
    // Find the last 9-byte frame header.
    const last_frame_start = buf.items.len - 9; // empty payload, just header
    const flags = buf.items[last_frame_start + 4];
    try std.testing.expect(flags & H2Connection.FLAG_END_STREAM != 0);
}
