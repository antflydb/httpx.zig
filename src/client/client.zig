//! HTTP Client Implementation for httpx.zig
//!
//! HTTP/1.1 and HTTP/2 client over TCP with optional TLS (HTTPS).
//!
//! ## HTTP/2 Support
//!
//! Set `http2_enabled` or `force_http2` in `ClientConfig`. The client uses
//! "prior knowledge" mode (RFC 7540 §3.4), sending the h2 connection preface
//! directly. ALPN negotiation is not available (Zig stdlib limitation).
//!
//! One h2 connection is maintained per host:port in `h2_conns`. When the Io
//! backend supports fibers, a background receive-loop fiber pumps frames
//! continuously, enabling true stream multiplexing — multiple request fibers
//! can share the connection, with writes serialized via `write_mutex` and
//! per-stream completion signaled via `Io.Event`. Without fiber support,
//! frames are pumped inline (one request at a time).

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
const socket_mod = @import("../net/socket.zig");
const Socket = socket_mod.Socket;
const Address = socket_mod.Address;
const SocketIoReader = socket_mod.SocketIoReader;
const SocketIoWriter = socket_mod.SocketIoWriter;
const SliceIoReader = socket_mod.SliceIoReader;
const PrefixedReader = socket_mod.PrefixedReader;
const ContentLengthReader = socket_mod.ContentLengthReader;
const ChunkedBodyReader = socket_mod.ChunkedBodyReader;
const Parser = @import("../protocol/parser.zig").Parser;
const TlsConfig = @import("../tls/tls.zig").TlsConfig;
const TlsSession = @import("../tls/tls.zig").TlsSession;
const ConnectionPool = @import("pool.zig").ConnectionPool;
const TlsPool = @import("pool.zig").TlsPool;
const TlsConnection = @import("pool.zig").TlsConnection;
const common = @import("../util/common.zig");
const flate = std.compress.flate;
const h2_mod = @import("../protocol/h2_connection.zig");
const H2Connection = h2_mod.H2Connection;
const hpack = @import("../protocol/hpack.zig");
const Stream = @import("../protocol/stream.zig").Stream;

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
    /// Enable HTTP/2 via "prior knowledge" mode (RFC 7540 §3.4).
    /// The client sends the h2 preface directly without ALPN negotiation.
    /// When Zig's stdlib exposes ALPN, this will additionally negotiate h2.
    http2_enabled: bool = false,
    /// Alias for `http2_enabled`. When true, the client always speaks HTTP/2
    /// to every host, regardless of ALPN (which the stdlib doesn't support yet).
    force_http2: bool = false,
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

/// A pooled HTTP/2 connection: socket + optional TLS + H2Connection state.
/// Heap-allocated for pointer stability (TlsSession stores internal pointers).
/// When fiber support is available, a background receive-loop fiber pumps
/// frames continuously, enabling true stream multiplexing on one connection.
const H2PoolEntry = struct {
    socket: Socket,
    session: TlsSession,
    h2: H2Connection,
    is_tls: bool,
    broken: bool = false,
    /// Tracks the background receive-loop fiber (if spawned).
    recv_group: Io.Group = Io.Group.init,
    /// True when a receive-loop fiber is actively pumping frames.
    recv_running: bool = false,
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
    /// Cached HTTP/2 connections keyed by "host:port".
    h2_conns: std.StringHashMapUnmanaged(*H2PoolEntry) = .{},

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

        // Clean up cached HTTP/2 connections.
        var h2_it = self.h2_conns.iterator();
        while (h2_it.next()) |entry| {
            const e = entry.value_ptr.*;
            // Close the socket first so the receive loop's blocking read
            // returns ConnectionClosed, allowing the fiber to exit cleanly.
            e.socket.close();
            // Wait for the receive-loop fiber to finish before tearing down.
            e.recv_group.await(self.io) catch {};
            e.h2.deinit();
            if (e.is_tls) e.session.deinit();
            self.allocator.destroy(e);
            self.allocator.free(entry.key_ptr.*);
        }
        self.h2_conns.deinit(self.allocator);
    }

    /// Adds an interceptor to the client.
    pub fn addInterceptor(self: *Self, interceptor: Interceptor) !void {
        try self.interceptors.append(self.allocator, interceptor);
    }

    /// Makes an HTTP request.
    pub fn request(self: *Self, method: types.Method, url: []const u8, reqOpts: RequestOptions) !Response {
        return self.requestInternal(method, url, reqOpts, 0);
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
                        self.io.sleep(Io.Duration.fromMilliseconds(@intCast(delay_ms)), .awake) catch {};
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
                    self.io.sleep(Io.Duration.fromMilliseconds(@intCast(delay_ms)), .awake) catch {};
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

        // HTTP/2 "prior knowledge" path (RFC 7540 §3.4).
        // Reuses a pooled connection per host when available.
        if (self.config.http2_enabled or self.config.force_http2) {
            const is_tls = req.uri.isTls();
            const entry = try self.getOrCreateH2Conn(host, port, is_tls);
            const result = self.executeH2OnPooled(entry, req) catch |err| {
                entry.broken = true;
                return err;
            };
            // Mark broken if peer sent GOAWAY — next request gets a fresh connection.
            if (entry.h2.goaway_received) entry.broken = true;
            return result;
        }

        if (req.uri.isTls()) {
            if (self.config.keep_alive) {
                var tls_conn = try self.tls_pool.getConnection(host, port);
                var ok = false;
                defer {
                    if (ok) self.tls_pool.releaseConnection(tls_conn) else self.tls_pool.evictConnection(tls_conn);
                }

                try applyTimeouts(&tls_conn.socket, timeout_ms, write_timeout_ms);
                return self.executeOnTls(&tls_conn.session, req, &ok);
            }

            // Non-pooled TLS fallback (keep_alive disabled).
            const addr = try Address.resolve(self.io, host, port);
            var socket = try Socket.connect(addr, self.io);
            defer socket.close();
            try applyTimeouts(&socket, timeout_ms, write_timeout_ms);
            return self.executeOnNewTls(&socket, host, req);
        }

        if (self.config.keep_alive) {
            var conn = try self.pool.getConnection(host, port);
            var ok = false;
            defer {
                if (ok) self.pool.releaseConnection(conn) else self.pool.evictConnection(conn);
            }

            try applyTimeouts(&conn.socket, timeout_ms, write_timeout_ms);
            return self.executeOnSocket(&conn.socket, req, &ok);
        }

        const addr = try Address.resolve(self.io, host, port);
        var socket = try Socket.connect(addr, self.io);
        defer socket.close();
        try applyTimeouts(&socket, timeout_ms, write_timeout_ms);
        return self.executeOnSocket(&socket, req, null);
    }

    /// Sends request and reads response over a plain TCP socket.
    /// If `keep_alive_out` is non-null, sets it based on the response's keep-alive header.
    fn executeOnSocket(self: *Self, socket: *Socket, req: *Request, keep_alive_out: ?*bool) !Response {
        try req.serialize(socket.writer());
        var res = try self.readResponse(socket, req.method);
        if (keep_alive_out) |out| {
            out.* = res.headers.isKeepAlive(.HTTP_1_1);
        }
        return res;
    }

    /// Sends request and reads response over an established TLS session.
    /// If `keep_alive_out` is non-null, sets it based on the response's keep-alive header.
    fn executeOnTls(self: *Self, session: *TlsSession, req: *Request, keep_alive_out: ?*bool) !Response {
        const w = try session.getWriter();
        try req.serialize(w);
        const r = try session.getReader();
        var res = try self.readResponse(r, req.method);
        if (keep_alive_out) |out| {
            out.* = res.headers.isKeepAlive(.HTTP_1_1);
        }
        return res;
    }

    /// Creates a new TLS session on a socket and executes a request.
    fn executeOnNewTls(self: *Self, socket: *Socket, host: []const u8, req: *Request) !Response {
        const tls_cfg = if (self.config.verify_ssl) TlsConfig.init(self.allocator) else TlsConfig.insecure(self.allocator);
        var session = TlsSession.init(tls_cfg, self.io);
        defer session.deinit();
        session.attachSocket(socket);
        try session.handshake(host);
        return self.executeOnTls(&session, req, null);
    }

    /// Gets or creates a pooled HTTP/2 connection for the given host:port.
    /// The connection preface and SETTINGS exchange happen once on creation;
    /// subsequent requests reuse the same TCP/TLS + H2Connection state.
    fn getOrCreateH2Conn(self: *Self, host: []const u8, port: u16, is_tls: bool) !*H2PoolEntry {
        var key_buf: [280]u8 = undefined;
        const key = std.fmt.bufPrint(&key_buf, "{s}:{d}", .{ host, port }) catch return error.InvalidUri;

        // Return existing healthy connection.
        if (self.h2_conns.get(key)) |entry| {
            if (!entry.broken and !entry.h2.goaway_received) return entry;
            if (entry.h2.goaway_received) entry.broken = true;
            // Remove and destroy broken entry.
            if (self.h2_conns.fetchRemove(key)) |removed| {
                const e = removed.value;
                e.socket.close();
                e.recv_group.await(self.io) catch {};
                e.h2.deinit();
                if (e.is_tls) e.session.deinit();
                self.allocator.destroy(e);
                self.allocator.free(removed.key);
            }
        }

        // Create a new connection.
        const entry = try self.allocator.create(H2PoolEntry);
        errdefer self.allocator.destroy(entry);

        const addr = try Address.resolve(self.io, host, port);
        entry.socket = try Socket.connect(addr, self.io);
        errdefer entry.socket.close();
        entry.socket.setNoDelay(true) catch {};
        entry.socket.setKeepAlive(true) catch {};

        entry.is_tls = is_tls;
        entry.broken = false;

        if (is_tls) {
            var tls_cfg = if (self.config.verify_ssl) TlsConfig.init(self.allocator) else TlsConfig.insecure(self.allocator);
            tls_cfg.alpn_protocols = &.{ "h2", "http/1.1" };
            entry.session = TlsSession.init(tls_cfg, self.io);
            errdefer entry.session.deinit();
            entry.session.attachSocket(&entry.socket);
            try entry.session.handshake(host);
        } else {
            // Initialize a dummy session (deinit is safe on un-handshaked session).
            entry.session = TlsSession.init(TlsConfig.init(self.allocator), self.io);
        }

        entry.h2 = H2Connection.initClient(self.allocator, self.io);
        entry.h2.max_stream_data_size = self.config.max_response_size;
        errdefer entry.h2.deinit();

        // Perform h2 handshake: preface + SETTINGS exchange.
        if (is_tls) {
            const w = try entry.session.getWriter();
            try entry.h2.sendClientPreface(w);
            const r = try entry.session.getReader();
            try self.exchangeH2Settings(&entry.h2, r, w);
        } else {
            try entry.h2.sendClientPreface(&entry.socket);
            try self.exchangeH2Settings(&entry.h2, &entry.socket, &entry.socket);
        }

        // Spawn a background receive-loop fiber so multiple request fibers
        // can share this connection via stream multiplexing.
        if (entry.recv_group.concurrent(self.io, h2RecvLoopFiber, .{entry})) {
            entry.recv_running = true;
        } else |_| {
            // No fiber support — fall back to inline frame pumping per request.
        }

        const owned_key = try std.fmt.allocPrint(self.allocator, "{s}:{d}", .{ host, port });
        errdefer self.allocator.free(owned_key);
        try self.h2_conns.put(self.allocator, owned_key, entry);
        return entry;
    }

    /// Reads frames until the server's initial SETTINGS has been received and ACKed.
    fn exchangeH2Settings(self: *Self, h2: *H2Connection, reader: anytype, writer: anytype) !void {
        var settings_received = false;
        while (!settings_received) {
            var frame = try h2.readFrame(reader);
            defer frame.deinit(self.allocator);
            if (frame.header.frame_type == .settings and frame.header.flags & H2Connection.FLAG_ACK == 0) {
                try h2.handleSettings(&frame, writer);
                settings_received = true;
            } else {
                _ = try h2.dispatchFrame(&frame, writer);
            }
        }
    }

    /// Background receive-loop fiber for multiplexed H2 connections.
    /// Continuously pumps frames until GOAWAY or connection error.
    fn h2RecvLoopFiber(entry: *H2PoolEntry) Io.Cancelable!void {
        if (entry.is_tls) {
            const r = entry.session.getReader() catch {
                entry.broken = true;
                return;
            };
            const w = entry.session.getWriter() catch {
                entry.broken = true;
                return;
            };
            entry.h2.runReceiveLoop(r, w) catch {};
        } else {
            entry.h2.runReceiveLoop(&entry.socket, &entry.socket) catch {};
        }
        entry.broken = true;
    }

    /// Executes a request on a pooled H2 connection. Creates a stream, sends
    /// the request, pumps frames until complete, and extracts the response.
    ///
    /// In multiplexed mode (recv_running=true), the background receive fiber
    /// pumps frames while this fiber waits on a per-stream event.
    /// In fallback mode, frames are pumped inline via awaitStreamComplete.
    fn executeH2OnPooled(self: *Self, entry: *H2PoolEntry, req: *Request) !Response {
        const h2 = &entry.h2;
        if (h2.goaway_received) {
            entry.broken = true;
            return error.ConnectionClosed;
        }
        const stream = try h2.stream_manager.createStream();
        const stream_id = stream.id;
        errdefer h2.stream_manager.removeStream(stream_id);

        // Build request pseudo-headers.
        const method_str = if (req.method == .CUSTOM)
            req.custom_method orelse "CUSTOM"
        else
            req.method.toString();
        const scheme = req.uri.scheme orelse "http";
        const authority = req.uri.host orelse return error.InvalidUri;
        var path_buf = std.ArrayListUnmanaged(u8).empty;
        defer path_buf.deinit(self.allocator);
        const alw = arrayListWriter(&path_buf, self.allocator);
        try alw.writeAll(req.uri.path);
        if (req.uri.query) |q| {
            try alw.writeAll("?");
            try alw.writeAll(q);
        }
        const path = path_buf.items;

        var extra = std.ArrayListUnmanaged(hpack.HeaderEntry).empty;
        defer extra.deinit(self.allocator);
        for (req.headers.entries.items) |he| {
            if (std.ascii.eqlIgnoreCase(he.name, "host")) continue;
            if (std.ascii.eqlIgnoreCase(he.name, "connection")) continue;
            if (std.ascii.eqlIgnoreCase(he.name, "transfer-encoding")) continue;
            if (std.ascii.eqlIgnoreCase(he.name, "upgrade")) continue;
            try extra.append(self.allocator, .{ .name = he.name, .value = he.value });
        }

        const h2_headers = try H2Connection.buildRequestHeaders(
            method_str, path, scheme, authority, extra.items, self.allocator,
        );
        defer self.allocator.free(h2_headers);

        const has_body = req.body != null;

        if (entry.recv_running) {
            // Multiplexed mode: background fiber pumps frames; we wait on a
            // per-stream completion semaphore that the receive loop posts.
            var sem: Io.Semaphore = .{ .permits = 0 };
            stream.completion_sem = &sem;
            // Re-fetch the stream pointer for cleanup since the backing
            // map may have rehashed while we were blocked on I/O.
            defer if (h2.stream_manager.getStream(stream_id)) |s| {
                s.completion_sem = null;
            };

            // Serialize frame writes via the connection's write mutex.
            {
                h2.write_mutex.lockUncancelable(self.io);
                defer h2.write_mutex.unlock(self.io);
                if (entry.is_tls) {
                    const w = try entry.session.getWriter();
                    try h2.sendHeaders(w, stream_id, h2_headers, !has_body);
                    if (req.body) |body| try h2.writeDataBlocking(w, stream_id, body, true);
                } else {
                    try h2.sendHeaders(&entry.socket, stream_id, h2_headers, !has_body);
                    if (req.body) |body| try h2.writeDataBlocking(&entry.socket, stream_id, body, true);
                }
            }

            // Wait for the receive loop to deliver the response.
            sem.waitUncancelable(self.io);
        } else {
            // Fallback mode: pump frames inline (no fiber support).
            if (entry.is_tls) {
                const r = try entry.session.getReader();
                const w = try entry.session.getWriter();
                try h2.sendHeaders(w, stream_id, h2_headers, !has_body);
                if (req.body) |body| try h2.writeData(w, stream_id, body, true);
                try h2.awaitStreamComplete(r, w, stream_id);
            } else {
                try h2.sendHeaders(&entry.socket, stream_id, h2_headers, !has_body);
                if (req.body) |body| try h2.writeData(&entry.socket, stream_id, body, true);
                try h2.awaitStreamComplete(&entry.socket, &entry.socket, stream_id);
            }
        }

        // Extract response from mailbox.
        const s = h2.stream_manager.getStream(stream_id) orelse return error.InvalidResponse;
        defer h2.stream_manager.removeStream(stream_id);
        if (s.stream_error) |err| return err;

        // Headers were decoded in deliverToMailbox (receive loop) to avoid
        // concurrent HPACK decode races on the shared hpack_ctx.
        const decoded_headers = s.request_headers orelse return error.InvalidResponse;

        var status_code: ?u16 = null;
        var response_headers = Headers.init(self.allocator);
        errdefer response_headers.deinit();

        for (decoded_headers) |h| {
            if (mem.eql(u8, h.name, ":status")) {
                status_code = std.fmt.parseInt(u16, h.value, 10) catch return error.InvalidResponse;
            } else if (h.name.len > 0 and h.name[0] != ':') {
                try response_headers.append(h.name, h.value);
            }
        }

        const code = status_code orelse return error.InvalidResponse;
        var res = Response.init(self.allocator, code);
        res.version = .HTTP_2;
        res.headers.deinit();
        res.headers = response_headers;

        if (s.data_buf.items.len > 0) {
            if (s.data_buf.items.len > self.config.max_response_size) return error.ResponseTooLarge;
            res.body = try self.allocator.dupe(u8, s.data_buf.items);
            res.body_owned = true;
        }

        return res;
    }

    /// Incremental reader for an HTTP/2 response body.
    /// Reads DATA frame payloads as they arrive from the receive loop.
    pub const H2StreamReader = struct {
        stream: *Stream,
        io: Io,
        h2: *H2Connection,
        entry: *H2PoolEntry,
        data_event: *Io.Event,
        allocator: Allocator,
        read_timeout: Io.Timeout = .none,

        /// Reads up to `buf.len` bytes. Blocks until data is available.
        /// Returns 0 at EOF. Returns error.Timeout if no data arrives
        /// within the configured read_timeout.
        pub fn read(self: *H2StreamReader, buf: []u8) !usize {
            while (true) {
                const avail = self.stream.data_buf.items.len - self.stream.read_offset;
                if (avail > 0) {
                    const n = @min(avail, buf.len);
                    const start = self.stream.read_offset;
                    @memcpy(buf[0..n], self.stream.data_buf.items[start..][0..n]);
                    self.stream.read_offset += n;
                    if (self.stream.read_offset >= Stream.compact_threshold) {
                        self.stream.compactDataBuf();
                    }
                    return n;
                }
                if (self.stream.stream_error) |err| return err;
                if (self.stream.completed) return 0;

                // Reset event, re-check buffer (handles race with receive loop),
                // then wait with timeout.
                self.data_event.reset();
                const avail2 = self.stream.data_buf.items.len - self.stream.read_offset;
                if (avail2 > 0) continue;
                if (self.stream.stream_error) |err| return err;
                if (self.stream.completed) return 0;

                self.data_event.waitTimeout(self.io, self.read_timeout) catch |err| switch (err) {
                    error.Timeout => return error.Timeout,
                    error.Canceled => return error.Canceled,
                };
            }
        }

        /// Releases the stream. Sends RST_STREAM(CANCEL) if the stream
        /// hasn't completed, telling the server to stop sending DATA frames.
        pub fn close(self: *H2StreamReader) void {
            const stream_id = self.stream.id;
            const completed = self.stream.completed;
            self.stream.data_event = null;
            self.stream.completion_sem = null;

            if (!completed) {
                self.h2.write_mutex.lockUncancelable(self.io);
                defer self.h2.write_mutex.unlock(self.io);
                if (self.entry.is_tls) {
                    if (self.entry.session.getWriter()) |w|
                        self.h2.sendRstStream(w, stream_id, .cancel) catch {}
                    else |_| {}
                } else {
                    self.h2.sendRstStream(&self.entry.socket, stream_id, .cancel) catch {};
                }
            }

            self.h2.stream_manager.removeStream(stream_id);
            self.allocator.destroy(self.data_event);
        }
    };

    /// Response from a streaming H2 request. Contains response headers
    /// and an incremental reader for the response body.
    pub const H2StreamResponse = struct {
        status_code: u16,
        headers: Headers,
        reader: H2StreamReader,

        pub fn deinit(self: *H2StreamResponse) void {
            self.reader.close();
            self.headers.deinit();
        }
    };

    /// Sends an HTTP/2 request and returns response headers + an incremental
    /// body reader. The caller reads DATA frames as they arrive without
    /// waiting for END_STREAM. Requires multiplexed mode (recv_running=true).
    pub fn requestStream(self: *Self, req: *Request) !H2StreamResponse {
        const host = req.uri.host orelse return error.InvalidUri;
        const is_tls = if (req.uri.scheme) |s| mem.eql(u8, s, "https") else false;
        const port = req.uri.port orelse if (is_tls) @as(u16, 443) else @as(u16, 80);
        const entry = try self.getOrCreateH2Conn(host, port, is_tls);
        if (!entry.recv_running) return error.MultiplexingRequired;

        const h2 = &entry.h2;
        if (h2.goaway_received) {
            entry.broken = true;
            return error.ConnectionClosed;
        }
        const stream = try h2.stream_manager.createStream();
        const stream_id = stream.id;
        errdefer h2.stream_manager.removeStream(stream_id);

        // Heap-allocate event for pointer stability and timed waits.
        const data_event = try self.allocator.create(Io.Event);
        data_event.* = .unset;
        stream.data_event = data_event;
        errdefer {
            stream.data_event = null;
            self.allocator.destroy(data_event);
        }

        // Build request pseudo-headers.
        const method_str = if (req.method == .CUSTOM)
            req.custom_method orelse "CUSTOM"
        else
            req.method.toString();
        const scheme = req.uri.scheme orelse "http";
        const authority = host;
        var path_buf = std.ArrayListUnmanaged(u8).empty;
        defer path_buf.deinit(self.allocator);
        const alw = arrayListWriter(&path_buf, self.allocator);
        try alw.writeAll(req.uri.path);
        if (req.uri.query) |q| {
            try alw.writeAll("?");
            try alw.writeAll(q);
        }
        const path = path_buf.items;

        var extra = std.ArrayListUnmanaged(hpack.HeaderEntry).empty;
        defer extra.deinit(self.allocator);
        for (req.headers.entries.items) |he| {
            if (std.ascii.eqlIgnoreCase(he.name, "host")) continue;
            if (std.ascii.eqlIgnoreCase(he.name, "connection")) continue;
            if (std.ascii.eqlIgnoreCase(he.name, "transfer-encoding")) continue;
            if (std.ascii.eqlIgnoreCase(he.name, "upgrade")) continue;
            try extra.append(self.allocator, .{ .name = he.name, .value = he.value });
        }

        const h2_headers = try H2Connection.buildRequestHeaders(
            method_str, path, scheme, authority, extra.items, self.allocator,
        );
        defer self.allocator.free(h2_headers);

        const has_body = req.body != null;

        // Send request frames under write mutex.
        {
            h2.write_mutex.lockUncancelable(self.io);
            defer h2.write_mutex.unlock(self.io);
            if (entry.is_tls) {
                const w = try entry.session.getWriter();
                try h2.sendHeaders(w, stream_id, h2_headers, !has_body);
                if (req.body) |body| try h2.writeDataBlocking(w, stream_id, body, true);
            } else {
                try h2.sendHeaders(&entry.socket, stream_id, h2_headers, !has_body);
                if (req.body) |body| try h2.writeDataBlocking(&entry.socket, stream_id, body, true);
            }
        }

        // Wait for HEADERS response (not END_STREAM) with timeout.
        const header_timeout: Io.Timeout = .{ .duration = .{
            .raw = Io.Duration.fromMilliseconds(self.config.timeouts.read_ms),
            .clock = .awake,
        } };
        while (!stream.got_headers and !stream.completed) {
            data_event.reset();
            if (stream.got_headers or stream.completed) break;
            data_event.waitTimeout(self.io, header_timeout) catch |err| switch (err) {
                error.Timeout => return error.Timeout,
                error.Canceled => return error.Canceled,
            };
        }
        if (stream.stream_error) |err| return err;

        // Headers were decoded in deliverToMailbox (receive loop) to avoid
        // concurrent HPACK decode races on the shared hpack_ctx.
        const decoded_headers = stream.request_headers orelse return error.InvalidResponse;

        var status_code: ?u16 = null;
        var response_headers = Headers.init(self.allocator);
        errdefer response_headers.deinit();

        for (decoded_headers) |h| {
            if (mem.eql(u8, h.name, ":status")) {
                status_code = std.fmt.parseInt(u16, h.value, 10) catch
                    return error.InvalidResponse;
            } else if (h.name.len > 0 and h.name[0] != ':') {
                try response_headers.append(h.name, h.value);
            }
        }

        return .{
            .status_code = status_code orelse return error.InvalidResponse,
            .headers = response_headers,
            .reader = .{
                .stream = stream,
                .io = self.io,
                .h2 = h2,
                .entry = entry,
                .data_event = data_event,
                .allocator = self.allocator,
            },
        };
    }

    /// Executes a single HTTP/2 request over an already-connected reader/writer pair.
    ///
    /// Performs the full h2 lifecycle: connection preface → SETTINGS exchange →
    /// send request as HEADERS (+DATA) → read response HEADERS + DATA frames.
    fn executeH2Request(self: *Self, reader: anytype, writer: anytype, req: *Request) !Response {
        var h2 = H2Connection.initClient(self.allocator, self.io);
        h2.max_stream_data_size = self.config.max_response_size;
        defer h2.deinit();

        // 1. Connection preface + SETTINGS.
        try h2.sendClientPreface(writer);

        // 2. Read server's SETTINGS, dispatch connection-level frames until we
        //    get past the initial handshake.
        var settings_received = false;
        while (!settings_received) {
            var frame = try h2.readFrame(reader);
            defer frame.deinit(self.allocator);
            if (frame.header.frame_type == .settings and frame.header.flags & H2Connection.FLAG_ACK == 0) {
                try h2.handleSettings(&frame, writer);
                settings_received = true;
            } else {
                _ = try h2.dispatchFrame(&frame, writer);
            }
        }

        // 3. Open a new stream and build request pseudo-headers.
        const stream = try h2.stream_manager.createStream();
        const stream_id = stream.id;

        const method_str = if (req.method == .CUSTOM)
            req.custom_method orelse "CUSTOM"
        else
            req.method.toString();
        const scheme = req.uri.scheme orelse "http";
        const authority = req.uri.host orelse return error.InvalidUri;
        var path_buf = std.ArrayListUnmanaged(u8).empty;
        defer path_buf.deinit(self.allocator);
        const alw = arrayListWriter(&path_buf, self.allocator);
        try alw.writeAll(req.uri.path);
        if (req.uri.query) |q| {
            try alw.writeAll("?");
            try alw.writeAll(q);
        }
        const path = path_buf.items;

        // Collect regular headers, skipping HTTP/2 connection-specific ones.
        var extra = std.ArrayListUnmanaged(hpack.HeaderEntry).empty;
        defer extra.deinit(self.allocator);
        for (req.headers.entries.items) |entry| {
            const lower = entry.name;
            if (std.ascii.eqlIgnoreCase(lower, "host")) continue;
            if (std.ascii.eqlIgnoreCase(lower, "connection")) continue;
            if (std.ascii.eqlIgnoreCase(lower, "transfer-encoding")) continue;
            if (std.ascii.eqlIgnoreCase(lower, "upgrade")) continue;
            try extra.append(self.allocator, .{ .name = entry.name, .value = entry.value });
        }

        const h2_headers = try H2Connection.buildRequestHeaders(
            method_str,
            path,
            scheme,
            authority,
            extra.items,
            self.allocator,
        );
        defer self.allocator.free(h2_headers);

        const has_body = req.body != null;
        try h2.sendHeaders(writer, stream_id, h2_headers, !has_body);

        // 4. Send body as DATA frame(s) if present.
        if (req.body) |body| {
            try h2.writeData(writer, stream_id, body, true);
        }

        // 5. Pump frames until the stream is complete (HEADERS + DATA + END_STREAM).
        //    processOneFrame handles connection-level frames and WINDOW_UPDATE internally.
        try h2.awaitStreamComplete(reader, writer, stream_id);

        // 6. Extract response from per-stream mailbox.
        const s = h2.stream_manager.getStream(stream_id) orelse return error.InvalidResponse;
        if (s.stream_error) |err| return err;

        // Headers were decoded in deliverToMailbox (receive loop) to avoid
        // concurrent HPACK decode races on the shared hpack_ctx.
        const decoded_headers = s.request_headers orelse return error.InvalidResponse;

        var status_code: ?u16 = null;
        var response_headers = Headers.init(self.allocator);
        errdefer response_headers.deinit();

        for (decoded_headers) |h| {
            if (mem.eql(u8, h.name, ":status")) {
                status_code = std.fmt.parseInt(u16, h.value, 10) catch return error.InvalidResponse;
            } else if (h.name.len > 0 and h.name[0] != ':') {
                try response_headers.append(h.name, h.value);
            }
        }

        const code = status_code orelse return error.InvalidResponse;
        var res = Response.init(self.allocator, code);
        res.version = .HTTP_2;
        res.headers.deinit();
        res.headers = response_headers;

        if (s.data_buf.items.len > 0) {
            if (s.data_buf.items.len > self.config.max_response_size) return error.ResponseTooLarge;
            res.body = try self.allocator.dupe(u8, s.data_buf.items);
            res.body_owned = true;
        }

        return res;
    }

    /// Unified response reader parameterized on the read source.
    /// `ReadSource` is either `*Socket` (TCP) or `*std.Io.Reader` (TLS/Io).
    ///
    /// Streaming pipeline: parse headers only → build Io.Reader chain
    /// (leftover → socket/TLS → content-length/chunked → decompress) → read into output.
    /// Only one copy of the body is ever in memory at a time.
    fn readResponse(self: *Self, source: anytype, req_method: types.Method) !Response {
        var parser = Parser.initResponse(self.allocator);
        defer parser.deinit();
        parser.max_body_size = self.config.max_response_size;
        parser.max_headers = self.config.max_response_headers;
        parser.headers_only = true;

        var buf: [16 * 1024]u8 = undefined;
        var total_read: usize = 0;
        var leftover: usize = 0;
        var informational_count: u8 = 0;

        while (true) {
            while (!parser.isComplete()) {
                if (leftover > 0) {
                    const consumed = try parser.feed(buf[0..leftover]);
                    if (consumed < leftover) {
                        std.mem.copyForwards(u8, buf[0 .. leftover - consumed], buf[consumed..leftover]);
                    }
                    leftover -= consumed;
                    continue;
                }

                if (leftover >= buf.len) return error.InvalidResponse;
                const n = recvFrom(source, buf[leftover..]) catch |err| return err;
                if (n == 0) break;
                total_read += n;
                if (total_read > self.config.max_response_size) return error.ResponseTooLarge;
                const consumed = try parser.feed(buf[0 .. leftover + n]);
                leftover = (leftover + n) - consumed;
            }

            parser.finishEof();
            if (!parser.isComplete()) return error.InvalidResponse;

            if (parser.status_code) |code| {
                if (code >= 100 and code < 200) {
                    informational_count += 1;
                    if (informational_count > 20) return error.TooManyInformationalResponses;
                    parser.reset();
                    parser.headers_only = true;
                    total_read = 0;
                    continue;
                }
            }
            break;
        }

        return self.buildStreamingResponse(&parser, source, buf[0..leftover], req_method);
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

    /// Wraps `source` (Socket or Io.Reader) into a uniform `Io.Reader` for the reader chain.
    fn sourceToIoReader(source: anytype, socket_reader: *SocketIoReader, io_buf: []u8) *Io.Reader {
        const Source = @TypeOf(source);
        if (Source == *Socket) {
            socket_reader.* = SocketIoReader.init(source, io_buf);
            return &socket_reader.reader_iface;
        } else if (Source == *std.Io.Reader) {
            return source;
        } else {
            @compileError("sourceToIoReader: unsupported source type " ++ @typeName(Source));
        }
    }

    /// Builds a Response by streaming the body through an Io.Reader chain.
    /// After headers are parsed, the chain is: leftover bytes → network → framing → decompress → output.
    fn buildStreamingResponse(self: *Self, parser: *Parser, source: anytype, leftover: []const u8, req_method: types.Method) !Response {
        const code = parser.status_code orelse return error.InvalidResponse;
        var res = Response.init(parser.allocator, code);
        errdefer res.deinit();

        // Move headers ownership from parser to response.
        res.headers.deinit();
        res.headers = parser.headers;
        parser.headers = Headers.init(parser.allocator);

        // RFC 7230 §3.3: Responses to HEAD and 1xx/204/304 status codes
        // MUST NOT contain a message body regardless of headers.
        const no_body_status = (code >= 100 and code < 200) or code == 204 or code == 304;
        const has_body = !no_body_status and req_method != .HEAD and
            (parser.chunked or (parser.content_length orelse 1) > 0);
        if (!has_body) return res;

        // Detect Content-Encoding for transparent decompression.
        const container: ?flate.Container = if (res.headers.get(HeaderName.CONTENT_ENCODING)) |raw_enc| blk: {
            const enc = std.mem.trim(u8, raw_enc, " \t");
            if (std.ascii.eqlIgnoreCase(enc, "gzip")) break :blk .gzip;
            if (std.ascii.eqlIgnoreCase(enc, "deflate")) break :blk .raw;
            break :blk null;
        } else null;

        // --- Build the Io.Reader chain (all stack-allocated) ---

        // Layer 0: Wrap the raw source (Socket or TLS Io.Reader) into an Io.Reader.
        var source_io_buf: [8192]u8 = undefined;
        var socket_reader: SocketIoReader = undefined;
        const raw_reader = sourceToIoReader(source, &socket_reader, &source_io_buf);

        // Layer 1: Prepend any leftover bytes from header parsing.
        var prefix_buf: [8192]u8 = undefined;
        var prefixed = PrefixedReader.init(leftover, raw_reader, &prefix_buf);
        const body_source: *Io.Reader = if (leftover.len > 0) &prefixed.reader_iface else raw_reader;

        // Layer 2: Apply transfer framing (Content-Length limit or chunked decode).
        var cl_buf: [8192]u8 = undefined;
        var cl_reader: ContentLengthReader = undefined;
        var chunked_buf: [8192]u8 = undefined;
        var chunked_reader: ChunkedBodyReader = undefined;

        const framed_reader: *Io.Reader = if (parser.chunked) blk: {
            chunked_reader = ChunkedBodyReader.init(body_source, &chunked_buf);
            break :blk &chunked_reader.reader_iface;
        } else if (parser.content_length) |len| blk: {
            if (len > std.math.maxInt(usize)) return error.ResponseTooLarge;
            cl_reader = ContentLengthReader.init(body_source, @intCast(len), &cl_buf);
            break :blk &cl_reader.reader_iface;
        } else blk: {
            // No Content-Length, not chunked — body delimited by connection close.
            break :blk body_source;
        };

        // Layer 3: Optional decompression.
        var decompress_window: [flate.max_window_len]u8 = undefined;
        var decompressor: flate.Decompress = undefined;

        const final_reader: *Io.Reader = if (container) |ctr| blk: {
            decompressor = flate.Decompress.init(framed_reader, ctr, &decompress_window);
            break :blk &decompressor.reader;
        } else framed_reader;

        // --- Read from the chain into a single output buffer ---
        var result = std.ArrayListUnmanaged(u8).empty;
        errdefer result.deinit(self.allocator);

        // Pre-allocate hint: use content_length if known (and not compressed).
        if (container == null) {
            if (parser.content_length) |len| {
                if (len <= std.math.maxInt(usize)) {
                    try result.ensureTotalCapacity(self.allocator, @intCast(len));
                }
            }
        }

        const max_size = self.config.max_response_size;
        var read_buf: [16 * 1024]u8 = undefined;
        while (true) {
            var iov = [_][]u8{read_buf[0..]};
            const n = final_reader.vtable.readVec(final_reader, &iov) catch |err| switch (err) {
                error.EndOfStream => break,
                else => return if (container != null) error.DecompressionFailed else error.InvalidResponse,
            };
            if (n == 0) break;
            if (result.items.len + n > max_size) return error.ResponseTooLarge;
            try result.appendSlice(self.allocator, read_buf[0..n]);
        }

        if (result.items.len > 0) {
            res.body = try result.toOwnedSlice(self.allocator);
            res.body_owned = true;
        }

        // Remove encoding/length headers when decompression was applied.
        if (container != null) {
            _ = res.headers.remove(HeaderName.CONTENT_ENCODING);
            _ = res.headers.remove(HeaderName.CONTENT_LENGTH);
        }

        return res;
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
        // Collect Set-Cookie values outside the lock to minimize contention.
        for (res.headers.entries.items) |entry| {
            if (!std.ascii.eqlIgnoreCase(entry.name, HeaderName.SET_COOKIE)) continue;
            const pair = common.parseSetCookiePair(entry.value) orelse continue;
            self.cookie_mutex.lockUncancelable(self.io);
            defer self.cookie_mutex.unlock(self.io);
            try self.setCookieLocked(pair.name, pair.value);
        }
    }

    const containsCrLf = @import("../core/headers.zig").containsCrLf;

    /// Returns true if a cookie name or value contains characters that could
    /// enable header injection (CR, LF) or malform the Cookie header (;).
    fn isSafeCookieToken(s: []const u8) bool {
        if (containsCrLf(s)) return false;
        return std.mem.indexOfScalar(u8, s, ';') == null;
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
        // count() includes the newly reserved slot, so >= max means at capacity.
        if (self.cookies.count() >= self.config.max_cookies) {
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
    const data = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 15\r\n\r\n{\"status\":\"ok\"}";

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

test "Client method convenience functions" {
    const allocator = std.testing.allocator;
    var client = Client.init(allocator, std.testing.io);
    defer client.deinit();

    // Compile-time check that convenience methods exist.
    const request_ptr: *const fn (*Client, types.Method, []const u8, RequestOptions) anyerror!Response = Client.request;
    const options_ptr: *const fn (*Client, []const u8, RequestOptions) anyerror!Response = Client.options;
    _ = request_ptr;
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

test "H2StreamReader reads pre-buffered data and returns EOF" {
    const allocator = std.testing.allocator;

    // Set up an H2Connection with a stream that has pre-buffered data.
    var h2 = H2Connection.initClient(allocator, std.testing.io);
    defer h2.deinit();

    const stream = try h2.stream_manager.createStream();
    const stream_id = stream.id;

    // Simulate receive loop having delivered data.
    try stream.data_buf.appendSlice(allocator, "hello world");
    stream.completed = true; // END_STREAM already received

    // Create a heap-allocated event (as requestStream would).
    const data_event = try allocator.create(Io.Event);
    data_event.* = .unset;
    stream.data_event = data_event;

    var reader = Client.H2StreamReader{
        .stream = stream,
        .io = std.testing.io,
        .h2 = &h2,
        .entry = undefined, // Not dereferenced: stream.completed=true so close() skips RST_STREAM.
        .data_event = data_event,
        .allocator = allocator,
    };

    // Read first chunk.
    var buf: [5]u8 = undefined;
    const n1 = try reader.read(&buf);
    try std.testing.expectEqual(@as(usize, 5), n1);
    try std.testing.expectEqualStrings("hello", &buf);

    // Read second chunk.
    var buf2: [10]u8 = undefined;
    const n2 = try reader.read(&buf2);
    try std.testing.expectEqual(@as(usize, 6), n2);
    try std.testing.expectEqualStrings(" world", buf2[0..n2]);

    // Next read should return 0 (EOF) since completed=true and no more data.
    const n3 = try reader.read(&buf2);
    try std.testing.expectEqual(@as(usize, 0), n3);

    // Clean up — close frees the event and removes the stream.
    reader.close();

    // Verify stream was removed.
    try std.testing.expect(h2.stream_manager.getStream(stream_id) == null);
}

// Tests for decompressBody and responseFromParser were removed — these methods
// were replaced by the streaming decompression pipeline in buildStreamingResponse.
