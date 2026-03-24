//! HTTP Client Implementation for httpx.zig
//!
//! HTTP/1.1 client over TCP with optional TLS (HTTPS).
//!
//! Notes:
//! - HTTP/2 and HTTP/3 types exist in `src/protocol/http.zig`, but this client
//!   currently speaks HTTP/1.1.

const std = @import("std");
const arrayListWriter = @import("../util/array_list_writer.zig").arrayListWriter;
const mem = std.mem;
const Allocator = mem.Allocator;
const Io = std.Io;

const types = @import("../core/types.zig");
const meta = @import("../core/meta.zig");
const Headers = @import("../core/headers.zig").Headers;
const HeaderName = @import("../core/headers.zig").HeaderName;
const Uri = @import("../core/uri.zig").Uri;
const Request = @import("../core/request.zig").Request;
const Response = @import("../core/response.zig").Response;
const Status = @import("../core/status.zig").Status;
const Socket = @import("../net/socket.zig").Socket;
const Address = @import("../net/socket.zig").Address;
const SocketIoReader = @import("../net/socket.zig").SocketIoReader;
const SocketIoWriter = @import("../net/socket.zig").SocketIoWriter;
const Parser = @import("../protocol/parser.zig").Parser;
const TlsConfig = @import("../tls/tls.zig").TlsConfig;
const TlsSession = @import("../tls/tls.zig").TlsSession;
const ConnectionPool = @import("pool.zig").ConnectionPool;
const TlsPool = @import("pool.zig").TlsPool;
const TlsConnection = @import("pool.zig").TlsConnection;
const common = @import("../util/common.zig");
const flate = std.compress.flate;

/// HTTP client configuration.
pub const ClientConfig = struct {
    base_url: ?[]const u8 = null,
    timeouts: types.Timeouts = .{},
    retry_policy: types.RetryPolicy = .{},
    redirect_policy: types.RedirectPolicy = .{},
    default_headers: ?[]const [2][]const u8 = null,
    user_agent: []const u8 = meta.default_user_agent,
    max_response_size: usize = types.default_max_body_size,
    max_response_headers: usize = 256,
    verify_ssl: bool = true,
    http2_enabled: bool = false,
    http3_enabled: bool = false,
    keep_alive: bool = true,
    pool_max_connections: u32 = 20,
    pool_max_per_host: u32 = 5,
    max_cookies: usize = 1000,
};

/// Per-request options.
pub const RequestOptions = struct {
    headers: ?[]const [2][]const u8 = null,
    body: ?[]const u8 = null,
    json: ?[]const u8 = null,
    timeout_ms: ?u64 = null,
    follow_redirects: ?bool = null,
};

/// Request interceptor function type.
pub const RequestInterceptor = *const fn (*Request, ?*anyopaque) anyerror!void;

/// Response interceptor function type.
pub const ResponseInterceptor = *const fn (*Response, ?*anyopaque) anyerror!void;

/// Interceptor with context.
pub const Interceptor = struct {
    request_fn: ?RequestInterceptor = null,
    response_fn: ?ResponseInterceptor = null,
    context: ?*anyopaque = null,
};

/// HTTP Client.
pub const Client = struct {
    allocator: Allocator,
    io: Io,
    config: ClientConfig,
    interceptors: std.ArrayListUnmanaged(Interceptor) = .empty,
    cookies: std.StringHashMapUnmanaged([]const u8) = .{},
    cookie_mutex: Io.Mutex = Io.Mutex.init,
    pool: ConnectionPool,
    tls_pool: TlsPool,

    const Self = @This();

    /// Creates a new HTTP client with default configuration.
    pub fn init(allocator: Allocator, io: Io) Self {
        return initWithConfig(allocator, io, .{});
    }

    /// Creates a new HTTP client with custom configuration.
    pub fn initWithConfig(allocator: Allocator, io: Io, config: ClientConfig) Self {
        const pool_cfg = @import("pool.zig").PoolConfig{
            .max_connections = config.pool_max_connections,
            .max_per_host = config.pool_max_per_host,
        };
        return .{
            .allocator = allocator,
            .io = io,
            .config = config,
            .pool = ConnectionPool.initWithConfig(allocator, io, pool_cfg, {}),
            .tls_pool = TlsPool.initWithConfig(allocator, io, pool_cfg, .{ .verify_ssl = config.verify_ssl }),
        };
    }

    /// Releases all allocated resources.
    pub fn deinit(self: *Self) void {
        self.interceptors.deinit(self.allocator);
        var it = self.cookies.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.cookies.deinit(self.allocator);
        self.pool.deinit();
        self.tls_pool.deinit();
    }

    /// Adds an interceptor to the client.
    pub fn addInterceptor(self: *Self, interceptor: Interceptor) !void {
        try self.interceptors.append(self.allocator, interceptor);
    }

    /// Makes an HTTP request.
    pub fn request(self: *Self, method: types.Method, url: []const u8, reqOpts: RequestOptions) !Response {
        return self.requestInternal(method, url, reqOpts, 0);
    }

    /// Alias for request() with a shorter name for application code.
    pub fn send(self: *Self, method: types.Method, url: []const u8, reqOpts: RequestOptions) !Response {
        return self.request(method, url, reqOpts);
    }

    /// Alias for GET requests in fetch-style client code.
    pub fn fetch(self: *Self, url: []const u8, reqOpts: RequestOptions) !Response {
        return self.get(url, reqOpts);
    }

    fn requestInternal(self: *Self, method: types.Method, url: []const u8, reqOpts: RequestOptions, depth: u32) !Response {
        const owned_url = if (self.config.base_url) |base|
            try std.fmt.allocPrint(self.allocator, "{s}{s}", .{ base, url })
        else
            null;
        defer if (owned_url) |u| self.allocator.free(u);
        const full_url = owned_url orelse url;

        var req = try Request.init(self.allocator, method, full_url);
        defer req.deinit();

        try req.headers.set(HeaderName.USER_AGENT, self.config.user_agent);

        if (self.config.default_headers) |hdrs| {
            for (hdrs) |h| {
                try req.headers.set(h[0], h[1]);
            }
        }

        if (reqOpts.headers) |hdrs| {
            for (hdrs) |h| {
                try req.headers.set(h[0], h[1]);
            }
        }

        if (reqOpts.body) |body| {
            try req.setBody(body);
        }

        if (reqOpts.json) |json_body| {
            try req.setJson(json_body);
        }

        // Request compressed responses unless the caller already set Accept-Encoding.
        if (!req.headers.contains(HeaderName.ACCEPT_ENCODING)) {
            try req.headers.set(HeaderName.ACCEPT_ENCODING, "gzip, deflate");
        }

        try self.attachCookies(&req);

        for (self.interceptors.items) |interceptor| {
            if (interceptor.request_fn) |f| {
                try f(&req, interceptor.context);
            }
        }

        var response = try self.executeRequest(&req, reqOpts.timeout_ms);
        errdefer response.deinit();

        try self.storeCookies(&response);

        for (self.interceptors.items) |interceptor| {
            if (interceptor.response_fn) |f| {
                try f(&response, interceptor.context);
            }
        }

        const should_follow = reqOpts.follow_redirects orelse
            self.config.redirect_policy.follow_redirects;
        if (should_follow and response.isRedirect()) {
            if (depth >= self.config.redirect_policy.max_redirects) {
                response.deinit();
                return error.TooManyRedirects;
            }

            const location = response.headers.get(HeaderName.LOCATION) orelse {
                response.deinit();
                return error.InvalidResponse;
            };

            const next_url = try self.resolveRedirectUrl(req.uri, location);
            defer self.allocator.free(next_url);

            const next_method = self.config.redirect_policy.getRedirectMethod(response.status.code, req.method);
            response.deinit();
            return self.requestInternal(next_method, next_url, reqOpts, depth + 1);
        }

        return response;
    }

    /// Executes the actual HTTP request.
    fn executeRequest(self: *Self, req: *Request, timeout_override_ms: ?u64) !Response {
        const policy = self.config.retry_policy;
        const can_retry_method = (!policy.retry_only_idempotent) or req.method.isIdempotent();

        var attempt: u32 = 0;
        while (true) {
            var res = self.executeRequestOnce(req, timeout_override_ms) catch |err| {
                if (policy.retry_on_connection_error and can_retry_method and attempt < policy.max_retries) {
                    attempt += 1;
                    const delay_ms = policy.calculateDelay(attempt);
                    if (delay_ms > 0) {
                        self.io.sleep(Io.Duration.fromMilliseconds(@intCast(delay_ms)), .monotonic) catch {};
                    }
                    continue;
                }
                return err;
            };

            if (can_retry_method and attempt < policy.max_retries and policy.shouldRetryStatus(res.status.code)) {
                res.deinit();
                attempt += 1;
                const delay_ms = policy.calculateDelay(attempt);
                if (delay_ms > 0) {
                    self.io.sleep(Io.Duration.fromMilliseconds(@intCast(delay_ms)), .monotonic) catch {};
                }
                continue;
            }

            return res;
        }
    }

    fn applyTimeouts(socket: *Socket, recv_ms: u64, send_ms: u64) !void {
        if (recv_ms > 0) try socket.setRecvTimeout(recv_ms);
        if (send_ms > 0) try socket.setSendTimeout(send_ms);
    }

    fn executeRequestOnce(self: *Self, req: *Request, timeout_override_ms: ?u64) !Response {
        const host = req.uri.host orelse return error.InvalidUri;
        const port = req.uri.effectivePort();
        // Use request_ms as a fallback ceiling for socket timeouts when the
        // specific read/write timeouts are not set via per-request override.
        const timeout_ms = timeout_override_ms orelse blk: {
            if (self.config.timeouts.request_ms > 0) break :blk self.config.timeouts.request_ms;
            break :blk self.config.timeouts.read_ms;
        };
        const write_timeout_ms = timeout_override_ms orelse blk: {
            if (self.config.timeouts.request_ms > 0) break :blk self.config.timeouts.request_ms;
            break :blk self.config.timeouts.write_ms;
        };

        if (req.uri.isTls()) {
            if (self.config.keep_alive) {
                var tls_conn = try self.tls_pool.getConnection(host, port);
                var ok = false;
                defer {
                    if (ok) {
                        self.tls_pool.releaseConnection(tls_conn);
                    } else {
                        self.tls_pool.evictConnection(tls_conn);
                    }
                }

                try applyTimeouts(&tls_conn.socket, timeout_ms, write_timeout_ms);

                const w = try tls_conn.session.getWriter();
                try req.serialize(w);

                const r = try tls_conn.session.getReader();
                var res = try self.readResponse(r);

                if (!res.headers.isKeepAlive(.HTTP_1_1)) {
                    ok = false;
                } else {
                    ok = true;
                }
                return res;
            }

            // Non-pooled TLS fallback (keep_alive disabled).
            const addr = try Address.resolve(self.io, host, port);

            var socket = try Socket.connect(addr, self.io);
            defer socket.close();

            try applyTimeouts(&socket, timeout_ms, write_timeout_ms);

            return self.executeTlsHttp(&socket, host, req);
        }

        if (self.config.keep_alive) {
            var conn = try self.pool.getConnection(host, port);
            var ok = false;
            defer {
                if (ok) {
                    self.pool.releaseConnection(conn);
                } else {
                    self.pool.evictConnection(conn);
                }
            }

            try applyTimeouts(&conn.socket, timeout_ms, write_timeout_ms);
            conn.socket.setKeepAlive(true) catch {};

            var bw = std.io.bufferedWriter(conn.socket.writer());
            try req.serialize(bw.writer().any());
            try bw.flush();
            var res = try self.readResponse(&conn.socket);
            if (!res.headers.isKeepAlive(.HTTP_1_1)) {
                // Non-keepalive response: evict the connection after this request.
                ok = false;
            } else {
                ok = true;
            }
            return res;
        }

        const addr = try Address.resolve(self.io, host, port);

        var socket = try Socket.connect(addr, self.io);
        defer socket.close();

        try applyTimeouts(&socket, timeout_ms, write_timeout_ms);

        var bw = std.io.bufferedWriter(socket.writer());
        try req.serialize(bw.writer().any());
        try bw.flush();
        return self.readResponse(&socket);
    }

    fn executeTlsHttp(self: *Self, socket: *Socket, host: []const u8, req: *Request) !Response {
        const tls_cfg = if (self.config.verify_ssl) TlsConfig.init(self.allocator) else TlsConfig.insecure(self.allocator);

        var session = TlsSession.init(tls_cfg, self.io);
        defer session.deinit();
        session.attachSocket(socket);
        try session.handshake(host);

        const w = try session.getWriter();
        try req.serialize(w);

        const r = try session.getReader();
        return self.readResponse(r);
    }

    /// Unified response reader parameterized on the read source.
    /// `ReadSource` is either `*Socket` (TCP) or `*std.Io.Reader` (TLS/Io).
    fn readResponse(self: *Self, source: anytype) !Response {
        var parser = Parser.initResponse(self.allocator);
        defer parser.deinit();
        parser.max_body_size = self.config.max_response_size;
        parser.max_headers = self.config.max_response_headers;

        var buf: [16 * 1024]u8 = undefined;
        var total_read: usize = 0;
        var leftover: usize = 0;
        var informational_count: u8 = 0;

        while (true) {
            while (!parser.isComplete()) {
                // First consume any leftover bytes from the previous iteration
                // (can happen when a 1xx response and the real response arrive
                // in the same TCP segment).
                if (leftover > 0) {
                    const consumed = try parser.feed(buf[0..leftover]);
                    if (consumed < leftover) {
                        std.mem.copyForwards(u8, buf[0 .. leftover - consumed], buf[consumed..leftover]);
                    }
                    leftover -= consumed;
                    continue;
                }

                const n = recvFrom(source, buf[leftover..]) catch |err| return err;
                if (n == 0) break;
                total_read += n;
                if (total_read > self.config.max_response_size) return error.ResponseTooLarge;
                const consumed = try parser.feed(buf[0 .. leftover + n]);
                leftover = (leftover + n) - consumed;
            }

            parser.finishEof();
            if (!parser.isComplete()) return error.InvalidResponse;

            // Skip 1xx informational responses (e.g. 100 Continue).
            // Cap at 20 to prevent a malicious server from keeping the connection
            // occupied indefinitely with an unbounded stream of 1xx responses.
            if (parser.status_code) |code| {
                if (code >= 100 and code < 200) {
                    informational_count += 1;
                    if (informational_count > 20) return error.TooManyInformationalResponses;
                    parser.reset();
                    // Reset byte counter for the real response. Leftover bytes
                    // from this recv will be re-consumed without another recv,
                    // so they don't need to be counted here.
                    total_read = 0;
                    continue;
                }
            }
            break;
        }

        return self.responseFromParser(&parser);
    }

    /// Read bytes from either a Socket or an Io.Reader into `buf`.
    fn recvFrom(source: anytype, buf: []u8) !usize {
        const Source = @TypeOf(source);
        if (Source == *Socket) {
            return source.recv(buf);
        } else if (Source == *std.Io.Reader) {
            var iov = [_][]u8{buf};
            return source.readVec(&iov) catch |err| switch (err) {
                error.EndOfStream => @as(usize, 0),
                else => err,
            };
        } else {
            @compileError("recvFrom: unsupported source type " ++ @typeName(Source));
        }
    }

    fn responseFromParser(self: *Self, parser: *Parser) !Response {
        const code = parser.status_code orelse return error.InvalidResponse;
        var res = Response.init(parser.allocator, code);
        errdefer res.deinit();

        // Move headers ownership from parser to response.
        res.headers.deinit();
        res.headers = parser.headers;
        parser.headers = Headers.init(parser.allocator);

        if (parser.getBody().len > 0) {
            res.body = try parser.body_buffer.toOwnedSlice(parser.allocator);
            res.body_owned = true;
        }

        // Transparently decompress gzip/deflate responses.
        if (res.body) |compressed_body| {
            if (res.headers.get(HeaderName.CONTENT_ENCODING)) |raw_enc| {
                const enc = std.mem.trim(u8, raw_enc, " \t");
                const container: ?flate.Container =
                    if (std.ascii.eqlIgnoreCase(enc, "gzip")) .gzip
                    else if (std.ascii.eqlIgnoreCase(enc, "deflate")) .zlib
                    else null;

                if (container) |ctr| {
                    const decompressed = try self.decompressBody(compressed_body, ctr);
                    if (res.body_owned) {
                        res.allocator.free(compressed_body);
                    }
                    res.body = decompressed;
                    res.body_owned = true;
                    // Body is now plain; remove encoding/length so callers
                    // see the uncompressed view.
                    _ = res.headers.remove(HeaderName.CONTENT_ENCODING);
                    _ = res.headers.remove(HeaderName.CONTENT_LENGTH);
                }
            }
        }

        return res;
    }

    /// Decompress a gzip or deflate (zlib) body that is already fully in memory.
    /// Uses a stack-allocated window — each fiber has its own stack, so this is
    /// safe for concurrent decompression without heap allocation or locking.
    fn decompressBody(self: *Self, body: []const u8, container: flate.Container) ![]u8 {
        // Build a SliceIoReader over the compressed bytes.
        var reader_buf: [4096]u8 = undefined;
        var slice_reader = SliceIoReader.init(body, &reader_buf);

        // Stack-allocated decompression window — fiber-safe without synchronization.
        var decompress_buf: [flate.max_window_len]u8 = undefined;

        var decompressor = flate.Decompress.init(&slice_reader.reader_iface, container, &decompress_buf);

        // Read all decompressed output into a growable list.
        var result = std.ArrayListUnmanaged(u8).empty;
        errdefer result.deinit(self.allocator);
        // Pre-allocate using compressed size as a lower-bound hint to reduce reallocs.
        try result.ensureTotalCapacity(self.allocator, body.len);

        const max_decompressed = self.config.max_response_size;
        var read_buf: [16 * 1024]u8 = undefined;
        while (true) {
            var iov = [_][]u8{read_buf[0..]};
            const n = decompressor.reader.readVec(&iov) catch |err| switch (err) {
                error.EndOfStream => break,
                else => return error.DecompressionFailed,
            };
            if (n == 0) break;
            if (result.items.len + n > max_decompressed) return error.ResponseTooLarge;
            try result.appendSlice(self.allocator, read_buf[0..n]);
        }

        return result.toOwnedSlice(self.allocator);
    }

    fn resolveRedirectUrl(self: *Self, base: Uri, location: []const u8) ![]u8 {
        // Absolute URL.
        if (mem.indexOf(u8, location, "://") != null) {
            // Only allow http/https schemes to prevent open redirects (e.g. file://, ftp://).
            // Use case-insensitive comparison per RFC 3986 §3.1 (schemes are case-insensitive).
            const has_http = location.len >= 7 and std.ascii.eqlIgnoreCase(location[0..7], "http://");
            const has_https = location.len >= 8 and std.ascii.eqlIgnoreCase(location[0..8], "https://");
            if (!has_http and !has_https) {
                return error.UnsafeRedirect;
            }
            return self.allocator.dupe(u8, location);
        }

        const scheme = base.scheme orelse "http";
        const host = base.host orelse return error.InvalidUri;
        const port = base.effectivePort();

        if (location.len > 0 and location[0] == '/') {
            return std.fmt.allocPrint(self.allocator, "{s}://{s}:{d}{s}", .{ scheme, host, port, location });
        }

        // Relative to current path.
        const base_path = base.path;
        const slash = mem.lastIndexOfScalar(u8, base_path, '/') orelse 0;
        const prefix = base_path[0 .. slash + 1];
        return std.fmt.allocPrint(self.allocator, "{s}://{s}:{d}{s}{s}", .{ scheme, host, port, prefix, location });
    }

    fn attachCookies(self: *Self, req: *Request) !void {
        self.cookie_mutex.lockUncancelable(self.io);
        defer self.cookie_mutex.unlock(self.io);
        if (self.cookies.count() == 0) return;

        var list = std.ArrayListUnmanaged(u8).empty;
        defer list.deinit(self.allocator);
        const writer = arrayListWriter(&list, self.allocator);

        var it = self.cookies.iterator();
        var first = true;
        while (it.next()) |entry| {
            if (!first) try writer.writeAll("; ");
            first = false;
            try writer.print("{s}={s}", .{ entry.key_ptr.*, entry.value_ptr.* });
        }

        if (list.items.len > 0) {
            try req.headers.set(HeaderName.COOKIE, list.items);
        }
    }

    fn storeCookies(self: *Self, res: *const Response) !void {
        self.cookie_mutex.lockUncancelable(self.io);
        defer self.cookie_mutex.unlock(self.io);

        for (res.headers.entries.items) |entry| {
            if (!std.ascii.eqlIgnoreCase(entry.name, HeaderName.SET_COOKIE)) continue;
            const pair = common.parseSetCookiePair(entry.value) orelse continue;
            try self.setCookieLocked(pair.name, pair.value);
        }
    }

    /// Returns true if a cookie name or value contains characters that could
    /// enable header injection (CR, LF) or malform the Cookie header (;).
    fn isSafeCookieToken(s: []const u8) bool {
        for (s) |c| {
            if (c == '\r' or c == '\n' or c == ';') return false;
        }
        return true;
    }

    fn setCookieLocked(self: *Self, name: []const u8, value: []const u8) !void {
        // Reject cookies with characters that enable header injection (CRLF)
        // or malform the Cookie header (semicolon in value).
        if (!isSafeCookieToken(name) or !isSafeCookieToken(value)) return;

        const gop = try self.cookies.getOrPut(self.allocator, name);

        if (gop.found_existing) {
            // Allocate new value BEFORE freeing old to avoid dangling pointer on OOM.
            const new_value = try self.allocator.dupe(u8, value);
            self.allocator.free(gop.value_ptr.*);
            gop.value_ptr.* = new_value;
            return;
        }

        // New entry path.
        // Cap check: only enforce for genuinely new cookies.
        if (self.cookies.count() - 1 >= self.config.max_cookies) {
            // Undo the slot reservation.
            self.cookies.removeByPtr(gop.key_ptr);
            return;
        }
        gop.key_ptr.* = try self.allocator.dupe(u8, name);
        errdefer {
            // If the value dupe below fails, undo the partial insertion
            // so the map doesn't hold a key with an uninitialized value.
            self.allocator.free(gop.key_ptr.*);
            self.cookies.removeByPtr(gop.key_ptr);
        }

        gop.value_ptr.* = try self.allocator.dupe(u8, value);
    }

    /// Adds or replaces a cookie in the in-memory client cookie jar.
    pub fn setCookie(self: *Self, name: []const u8, value: []const u8) !void {
        self.cookie_mutex.lockUncancelable(self.io);
        defer self.cookie_mutex.unlock(self.io);
        return self.setCookieLocked(name, value);
    }

    /// Returns a cookie value from the in-memory cookie jar.
    pub fn getCookie(self: *Self, name: []const u8) ?[]const u8 {
        self.cookie_mutex.lockUncancelable(self.io);
        defer self.cookie_mutex.unlock(self.io);
        return self.cookies.get(name);
    }

    /// Removes a cookie from the in-memory cookie jar.
    pub fn removeCookie(self: *Self, name: []const u8) bool {
        self.cookie_mutex.lockUncancelable(self.io);
        defer self.cookie_mutex.unlock(self.io);
        if (self.cookies.fetchRemove(name)) |removed| {
            self.allocator.free(removed.key);
            self.allocator.free(removed.value);
            return true;
        }
        return false;
    }

    /// Clears all cookies from the in-memory cookie jar.
    pub fn clearCookies(self: *Self) void {
        self.cookie_mutex.lockUncancelable(self.io);
        defer self.cookie_mutex.unlock(self.io);
        var it = self.cookies.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.cookies.clearRetainingCapacity();
    }

    /// Returns true if a cookie with the given name exists in the jar.
    pub fn hasCookie(self: *Self, name: []const u8) bool {
        self.cookie_mutex.lockUncancelable(self.io);
        defer self.cookie_mutex.unlock(self.io);
        return self.cookies.contains(name);
    }

    /// Returns the number of cookies currently stored in the jar.
    pub fn cookieCount(self: *Self) usize {
        self.cookie_mutex.lockUncancelable(self.io);
        defer self.cookie_mutex.unlock(self.io);
        return self.cookies.count();
    }

    /// GET request convenience method.
    pub fn get(self: *Self, url: []const u8, reqOpts: RequestOptions) !Response {
        return self.request(.GET, url, reqOpts);
    }

    /// POST request convenience method.
    pub fn post(self: *Self, url: []const u8, reqOpts: RequestOptions) !Response {
        return self.request(.POST, url, reqOpts);
    }

    /// PUT request convenience method.
    pub fn put(self: *Self, url: []const u8, reqOpts: RequestOptions) !Response {
        return self.request(.PUT, url, reqOpts);
    }

    /// DELETE request convenience method.
    pub fn delete(self: *Self, url: []const u8, reqOpts: RequestOptions) !Response {
        return self.request(.DELETE, url, reqOpts);
    }

    /// PATCH request convenience method.
    pub fn patch(self: *Self, url: []const u8, reqOpts: RequestOptions) !Response {
        return self.request(.PATCH, url, reqOpts);
    }

    /// HEAD request convenience method.
    pub fn head(self: *Self, url: []const u8, reqOpts: RequestOptions) !Response {
        return self.request(.HEAD, url, reqOpts);
    }

    /// OPTIONS request convenience method.
    pub fn options(self: *Self, url: []const u8, reqOpts: RequestOptions) !Response {
        return self.request(.OPTIONS, url, reqOpts);
    }
};

/// Adapter that exposes a `std.Io.Reader` backed by a `[]const u8` slice.
///
/// Used to feed in-memory compressed bytes to `std.compress.flate.Decompress`.
const SliceIoReader = struct {
    data: []const u8,
    pos: usize = 0,
    reader_iface: Io.Reader,

    const IoReaderHelpers = @import("../net/socket.zig").IoReaderHelpers;

    fn init(data: []const u8, buffer: []u8) SliceIoReader {
        return .{
            .data = data,
            .reader_iface = .{
                .vtable = &vtable,
                .buffer = buffer,
                .seek = 0,
                .end = 0,
            },
        };
    }

    fn parent(r: *Io.Reader) *SliceIoReader {
        return @fieldParentPtr("reader_iface", r);
    }

    fn readVec(r: *Io.Reader, bufs: [][]u8) Io.Reader.Error!usize {
        const p = parent(r);
        if (bufs.len == 0) return 0;
        const buf = bufs[0];
        const remaining = p.data[p.pos..];
        if (remaining.len == 0) return error.EndOfStream;
        const n = @min(buf.len, remaining.len);
        @memcpy(buf[0..n], remaining[0..n]);
        p.pos += n;
        return n;
    }

    const vtable: Io.Reader.VTable = .{
        .stream = IoReaderHelpers.stream,
        .discard = IoReaderHelpers.discard,
        .readVec = readVec,
        .rebase = IoReaderHelpers.rebase,
    };
};

test "Client initialization" {
    const allocator = std.testing.allocator;
    var client = Client.init(allocator, std.testing.io);
    defer client.deinit();

    try std.testing.expectEqualStrings(meta.default_user_agent, client.config.user_agent);
}

test "Client with config" {
    const allocator = std.testing.allocator;
    var client = Client.initWithConfig(allocator, std.testing.io, .{
        .base_url = "https://api.example.com",
        .user_agent = "TestClient/1.0",
    });
    defer client.deinit();

    try std.testing.expectEqualStrings("https://api.example.com", client.config.base_url.?);
}

test "Response parsing" {
    const allocator = std.testing.allocator;
    const data = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"status\":\"ok\"}";

    var parser = Parser.initResponse(allocator);
    defer parser.deinit();

    _ = try parser.feed(data);
    try std.testing.expect(parser.isComplete());

    const code = parser.status_code orelse return error.InvalidResponse;
    try std.testing.expectEqual(@as(u16, 200), code);
    try std.testing.expectEqualStrings("application/json", parser.headers.get("Content-Type").?);
}

test "Client stores Set-Cookie headers" {
    const allocator = std.testing.allocator;
    var client = Client.init(allocator, std.testing.io);
    defer client.deinit();

    var response = Response.init(allocator, 200);
    defer response.deinit();

    try response.headers.append("Set-Cookie", "session=abc123; Path=/; HttpOnly");
    try response.headers.append("Set-Cookie", "theme=dark; Path=/");

    try client.storeCookies(&response);

    try std.testing.expectEqualStrings("abc123", client.cookies.get("session").?);
    try std.testing.expectEqualStrings("dark", client.cookies.get("theme").?);
}

test "Client attaches Cookie header from jar" {
    const allocator = std.testing.allocator;
    var client = Client.init(allocator, std.testing.io);
    defer client.deinit();

    try client.setCookie("session", "abc123");
    try client.setCookie("theme", "dark");

    var request = try Request.init(allocator, .GET, "https://example.com/");
    defer request.deinit();

    try client.attachCookies(&request);

    const cookie_header = request.headers.get("Cookie") orelse return error.TestUnexpectedResult;
    try std.testing.expect(mem.indexOf(u8, cookie_header, "session=abc123") != null);
    try std.testing.expect(mem.indexOf(u8, cookie_header, "theme=dark") != null);
}

test "Client cookie jar public API" {
    const allocator = std.testing.allocator;
    var client = Client.init(allocator, std.testing.io);
    defer client.deinit();

    try client.setCookie("session", "abc123");
    try std.testing.expectEqualStrings("abc123", client.getCookie("session").?);

    const removed = client.removeCookie("session");
    try std.testing.expect(removed);
    try std.testing.expect(client.getCookie("session") == null);

    try client.setCookie("theme", "dark");
    try client.setCookie("lang", "en");
    client.clearCookies();
    try std.testing.expectEqual(@as(usize, 0), client.cookies.count());
}

test "Client send/fetch/options aliases" {
    const allocator = std.testing.allocator;
    var client = Client.init(allocator, std.testing.io);
    defer client.deinit();

    // Compile-time alias checks through function pointer assignment.
    const send_ptr: *const fn (*Client, types.Method, []const u8, RequestOptions) anyerror!Response = Client.send;
    const fetch_ptr: *const fn (*Client, []const u8, RequestOptions) anyerror!Response = Client.fetch;
    const options_ptr: *const fn (*Client, []const u8, RequestOptions) anyerror!Response = Client.options;
    _ = send_ptr;
    _ = fetch_ptr;
    _ = options_ptr;
}

test "Client hasCookie and cookieCount" {
    const allocator = std.testing.allocator;
    var client = Client.init(allocator, std.testing.io);
    defer client.deinit();

    try std.testing.expectEqual(@as(usize, 0), client.cookieCount());
    try std.testing.expect(!client.hasCookie("session"));

    try client.setCookie("session", "abc123");
    try std.testing.expectEqual(@as(usize, 1), client.cookieCount());
    try std.testing.expect(client.hasCookie("session"));
}

test "Client response size limit" {
    const config = ClientConfig{};
    try std.testing.expectEqual(@as(usize, 100 * 1024 * 1024), config.max_response_size);
}

test "Client config retry policy defaults" {
    const config = ClientConfig{};
    try std.testing.expectEqual(@as(u32, 3), config.retry_policy.max_retries);
}

test "Client config redirect policy defaults" {
    const config = ClientConfig{};
    try std.testing.expectEqual(@as(u32, 10), config.redirect_policy.max_redirects);
}

test "Client config keep alive default" {
    const config = ClientConfig{};
    try std.testing.expect(config.keep_alive);
}

test "Client interceptor management" {
    const allocator = std.testing.allocator;
    var client = Client.init(allocator, std.testing.io);
    defer client.deinit();

    try client.addInterceptor(.{
        .request_fn = null,
        .response_fn = null,
        .context = null,
    });

    try std.testing.expectEqual(@as(usize, 1), client.interceptors.items.len);
}

test "Client config base URL" {
    const allocator = std.testing.allocator;
    var client = Client.initWithConfig(allocator, std.testing.io, .{
        .base_url = "https://api.example.com",
    });
    defer client.deinit();

    try std.testing.expect(client.config.base_url != null);
    try std.testing.expectEqualStrings("https://api.example.com", client.config.base_url.?);
}

test "Client HTTP version default" {
    const config = ClientConfig{};
    try std.testing.expect(!config.http2_enabled);
    try std.testing.expect(!config.http3_enabled);
}

test "Client config max_response_headers default" {
    const config = ClientConfig{};
    try std.testing.expectEqual(@as(usize, 256), config.max_response_headers);
}

test "Client config limits are customizable" {
    const allocator = std.testing.allocator;
    var client = Client.initWithConfig(allocator, std.testing.io, .{
        .max_response_size = 1024,
        .max_response_headers = 32,
    });
    defer client.deinit();

    try std.testing.expectEqual(@as(usize, 1024), client.config.max_response_size);
    try std.testing.expectEqual(@as(usize, 32), client.config.max_response_headers);
}

test "SliceIoReader reads slice data" {
    const data = "hello, world!";
    var buf: [64]u8 = undefined;
    var reader = SliceIoReader.init(data, &buf);

    var out: [64]u8 = undefined;
    var iov = [_][]u8{out[0..]};
    const n = try reader.reader_iface.readVec(&iov);
    try std.testing.expectEqualStrings(data, out[0..n]);

    // Second read should return EndOfStream.
    var iov2 = [_][]u8{out[0..]};
    try std.testing.expectError(error.EndOfStream, reader.reader_iface.readVec(&iov2));
}

test "decompressBody gzip" {
    const allocator = std.testing.allocator;
    var client = Client.init(allocator, std.testing.io);
    defer client.deinit();

    // "Hello, compressed world!" gzip-compressed.
    const gzip_data = [_]u8{
        0x1f, 0x8b, 0x08, 0x00, 0x09, 0x5f, 0xc1, 0x69,
        0x00, 0x03, 0xf3, 0x48, 0xcd, 0xc9, 0xc9, 0xd7,
        0x51, 0x48, 0xce, 0xcf, 0x2d, 0x28, 0x4a, 0x2d,
        0x2e, 0x4e, 0x4d, 0x51, 0x28, 0xcf, 0x2f, 0xca,
        0x49, 0x51, 0x04, 0x00, 0x05, 0xbd, 0x53, 0x6e,
        0x18, 0x00, 0x00, 0x00,
    };

    const result = try client.decompressBody(&gzip_data, .gzip);
    defer allocator.free(result);

    try std.testing.expectEqualStrings("Hello, compressed world!", result);
}

test "decompressBody deflate (zlib)" {
    const allocator = std.testing.allocator;
    var client = Client.init(allocator, std.testing.io);
    defer client.deinit();

    // "Hello, compressed world!" zlib-compressed.
    const zlib_data = [_]u8{
        0x78, 0x9c, 0xf3, 0x48, 0xcd, 0xc9, 0xc9, 0xd7,
        0x51, 0x48, 0xce, 0xcf, 0x2d, 0x28, 0x4a, 0x2d,
        0x2e, 0x4e, 0x4d, 0x51, 0x28, 0xcf, 0x2f, 0xca,
        0x49, 0x51, 0x04, 0x00, 0x6e, 0xb1, 0x08, 0xdf,
    };

    const result = try client.decompressBody(&zlib_data, .zlib);
    defer allocator.free(result);

    try std.testing.expectEqualStrings("Hello, compressed world!", result);
}

test "responseFromParser decompresses gzip body" {
    const allocator = std.testing.allocator;
    var client = Client.init(allocator, std.testing.io);
    defer client.deinit();

    // Build a raw HTTP response with gzip Content-Encoding.
    const gzip_body = [_]u8{
        0x1f, 0x8b, 0x08, 0x00, 0x09, 0x5f, 0xc1, 0x69,
        0x00, 0x03, 0xf3, 0x48, 0xcd, 0xc9, 0xc9, 0xd7,
        0x51, 0x48, 0xce, 0xcf, 0x2d, 0x28, 0x4a, 0x2d,
        0x2e, 0x4e, 0x4d, 0x51, 0x28, 0xcf, 0x2f, 0xca,
        0x49, 0x51, 0x04, 0x00, 0x05, 0xbd, 0x53, 0x6e,
        0x18, 0x00, 0x00, 0x00,
    };

    var header_buf: [256]u8 = undefined;
    const header_str = std.fmt.bufPrint(&header_buf, "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: {d}\r\n\r\n", .{gzip_body.len}) catch unreachable;

    var raw = std.ArrayListUnmanaged(u8).empty;
    defer raw.deinit(allocator);
    try raw.appendSlice(allocator, header_str);
    try raw.appendSlice(allocator, &gzip_body);

    var parser = Parser.initResponse(allocator);
    defer parser.deinit();
    _ = try parser.feed(raw.items);
    parser.finishEof();
    try std.testing.expect(parser.isComplete());

    var response = try client.responseFromParser(&parser);
    defer response.deinit();

    // Body should be decompressed.
    try std.testing.expectEqualStrings("Hello, compressed world!", response.body.?);
    // Content-Encoding header should be removed.
    try std.testing.expect(response.headers.get(HeaderName.CONTENT_ENCODING) == null);
    // Content-Length should be removed (no longer matches).
    try std.testing.expect(response.headers.get(HeaderName.CONTENT_LENGTH) == null);
}
