//! HTTP Connection Pool for httpx.zig
//!
//! Provides connection pooling for HTTP clients:
//!
//! - Reusable TCP connections with keep-alive
//! - Per-host connection limits
//! - Automatic connection health checking
//! - Idle connection timeout and cleanup

const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const Io = std.Io;

const Socket = @import("../net/socket.zig").Socket;
const Address = @import("../net/socket.zig").Address;
const TlsConfig = @import("../tls/tls.zig").TlsConfig;
const TlsSession = @import("../tls/tls.zig").TlsSession;

/// Monotonic millisecond timestamp for connection health tracking.
fn milliTimestamp() i64 {
    if (builtin.os.tag == .macos) {
        // mach_absolute_time returns nanoseconds on Apple Silicon.
        return @intCast(std.c.mach_absolute_time() / std.time.ns_per_ms);
    } else {
        var ts: std.c.timespec = undefined;
        _ = std.c.clock_gettime(std.c.CLOCK.MONOTONIC, &ts);
        return @as(i64, ts.sec) * 1000 + @divFloor(@as(i64, ts.nsec), std.time.ns_per_ms);
    }
}

pub const PoolError = error{
    PoolExhausted,
    PoolExhaustedForHost,
};

/// Pooled connection representing a reusable socket.
pub const Connection = struct {
    socket: Socket,
    host: []const u8,
    port: u16,
    in_use: bool = false,
    broken: bool = false,
    created_at: i64,
    last_used: i64,
    requests_made: u32 = 0,

    const Self = @This();

    /// Marks the connection as in use.
    pub fn acquire(self: *Self) void {
        self.in_use = true;
        self.last_used = milliTimestamp();
    }

    /// Releases the connection back to the pool.
    pub fn release(self: *Self) void {
        self.in_use = false;
        self.last_used = milliTimestamp();
        self.requests_made += 1;
    }

    /// Returns true if the connection is healthy and reusable.
    pub fn isHealthy(self: *const Self, max_idle_ms: i64) bool {
        if (self.in_use) return false;
        if (self.broken) return false;
        const idle_time = milliTimestamp() - self.last_used;
        return idle_time < max_idle_ms;
    }

    /// Marks this connection as broken so it will not be reused.
    pub fn markBroken(self: *Self) void {
        self.broken = true;
    }

    /// Returns true if this connection should be evicted from the pool.
    pub fn shouldEvict(self: *const Self, idle_timeout_ms: i64, max_requests_per_connection: u32) bool {
        if (self.in_use) return false;
        if (self.broken) return true;
        if (self.requests_made >= max_requests_per_connection) return true;
        const idle_time = milliTimestamp() - self.last_used;
        return idle_time >= idle_timeout_ms;
    }

    /// Closes the underlying socket.
    pub fn close(self: *Self) void {
        self.socket.close();
    }
};

/// Connection pool configuration.
pub const PoolConfig = struct {
    max_connections: u32 = 20,
    max_per_host: u32 = 5,
    idle_timeout_ms: i64 = 60_000,
    max_requests_per_connection: u32 = 1000,
    health_check_interval_ms: i64 = 30_000,
};

/// Snapshot statistics for the connection pool.
pub const PoolStats = struct {
    total: usize,
    active: usize,
    idle: usize,
};

/// HTTP connection pool.
/// Connections are individually heap-allocated for pointer stability.
pub const ConnectionPool = struct {
    allocator: Allocator,
    io: Io,
    config: PoolConfig,
    connections: std.ArrayListUnmanaged(*Connection) = .empty,
    mutex: Io.Mutex = Io.Mutex.init,
    last_cleanup: i64 = 0,

    const Self = @This();

    /// Creates a new connection pool.
    pub fn init(allocator: Allocator, io: Io) Self {
        return initWithConfig(allocator, io, .{});
    }

    /// Creates a connection pool with custom configuration.
    pub fn initWithConfig(allocator: Allocator, io: Io, config: PoolConfig) Self {
        return .{
            .allocator = allocator,
            .io = io,
            .config = config,
        };
    }

    /// Releases all pool resources.
    pub fn deinit(self: *Self) void {
        for (self.connections.items) |conn| {
            conn.close();
            self.allocator.free(conn.host);
            self.allocator.destroy(conn);
        }
        self.connections.deinit(self.allocator);
    }

    /// Gets or creates a connection to the specified host.
    /// The returned pointer is stable for the lifetime of the connection.
    pub fn getConnection(self: *Self, host: []const u8, port: u16) !*Connection {
        {
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);

            // Periodic cleanup: evict stale/broken connections.
            const now = milliTimestamp();
            if (now - self.last_cleanup > self.config.health_check_interval_ms) {
                self.cleanupLocked();
                self.last_cleanup = now;
            }

            for (self.connections.items) |conn| {
                if (std.mem.eql(u8, conn.host, host) and conn.port == port) {
                    if (conn.isHealthy(self.config.idle_timeout_ms) and conn.requests_made < self.config.max_requests_per_connection) {
                        conn.acquire();
                        return conn;
                    }
                }
            }

            if (self.totalCount() >= self.config.max_connections) return PoolError.PoolExhausted;

            var host_count: u32 = 0;
            for (self.connections.items) |conn| {
                if (std.mem.eql(u8, conn.host, host) and conn.port == port) host_count += 1;
            }
            if (host_count >= self.config.max_per_host) return PoolError.PoolExhaustedForHost;
        }

        // Create the connection without holding the mutex (DNS + TCP connect may block).
        return self.createConnection(host, port);
    }

    /// Creates a new connection. Performs I/O without holding the pool mutex,
    /// then briefly locks to insert the new connection.
    fn createConnection(self: *Self, host: []const u8, port: u16) !*Connection {
        const host_owned = try self.allocator.dupe(u8, host);
        errdefer self.allocator.free(host_owned);

        const addr = try Address.resolve(self.io, host, port);

        var socket = try Socket.connect(addr, self.io);
        errdefer socket.close();

        const now = milliTimestamp();

        const conn = try self.allocator.create(Connection);
        errdefer self.allocator.destroy(conn);
        conn.* = .{
            .socket = socket,
            .host = host_owned,
            .port = port,
            .in_use = true,
            .created_at = now,
            .last_used = now,
        };

        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);

        // Re-check limits after re-acquiring the mutex — another fiber may have
        // raced and filled the pool while we were connecting.
        // Cleanup is handled by the errdefer blocks above.
        if (self.connections.items.len >= self.config.max_connections) {
            return PoolError.PoolExhausted;
        }
        var recheck_host_count: u32 = 0;
        for (self.connections.items) |c| {
            if (std.mem.eql(u8, c.host, host) and c.port == port) recheck_host_count += 1;
        }
        if (recheck_host_count >= self.config.max_per_host) {
            return PoolError.PoolExhaustedForHost;
        }

        try self.connections.append(self.allocator, conn);

        return conn;
    }

    /// Releases a connection back to the pool.
    pub fn releaseConnection(self: *Self, conn: *Connection) void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        conn.release();
        // Opportunistic cleanup on release.
        const now = milliTimestamp();
        if (now - self.last_cleanup > self.config.health_check_interval_ms) {
            self.cleanupLocked();
            self.last_cleanup = now;
        }
    }

    /// Removes a specific connection from the pool and frees its resources.
    /// Use this when a network error occurs instead of just closing the socket.
    pub fn evictConnection(self: *Self, conn: *Connection) void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);

        for (self.connections.items, 0..) |c, i| {
            if (c == conn) {
                _ = self.connections.swapRemove(i);
                break;
            }
        }

        conn.close();
        self.allocator.free(conn.host);
        self.allocator.destroy(conn);
    }

    /// Removes idle connections that have exceeded the timeout.
    pub fn cleanup(self: *Self) void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        self.cleanupLocked();
    }

    fn cleanupLocked(self: *Self) void {
        var i: usize = 0;
        while (i < self.connections.items.len) {
            const conn = self.connections.items[i];
            if (conn.shouldEvict(self.config.idle_timeout_ms, self.config.max_requests_per_connection)) {
                conn.close();
                self.allocator.free(conn.host);
                self.allocator.destroy(conn);
                _ = self.connections.swapRemove(i);
            } else {
                i += 1;
            }
        }
    }

    /// Returns the number of active connections.
    pub fn activeCount(self: *const Self) usize {
        var count: usize = 0;
        for (self.connections.items) |conn| {
            if (conn.in_use) count += 1;
        }
        return count;
    }

    /// Returns the total number of connections.
    pub fn totalCount(self: *const Self) usize {
        return self.connections.items.len;
    }

    /// Returns the number of idle connections.
    pub fn idleCount(self: *const Self) usize {
        return self.totalCount() - self.activeCount();
    }

    /// Returns the number of connections tracked for a specific host/port pair.
    pub fn hostConnectionCount(self: *const Self, host: []const u8, port: u16) usize {
        var count: usize = 0;
        for (self.connections.items) |conn| {
            if (std.mem.eql(u8, conn.host, host) and conn.port == port) {
                count += 1;
            }
        }
        return count;
    }

    /// Returns a snapshot of total/active/idle pool counts.
    pub fn stats(self: *const Self) PoolStats {
        const total = self.totalCount();
        const active = self.activeCount();
        return .{ .total = total, .active = active, .idle = total - active };
    }
};

/// A pooled TLS connection bundle.
///
/// Heap-allocated for pointer stability: `TlsSession` stores internal pointers
/// to its `SocketIoReader`/`SocketIoWriter`, which in turn reference the `Socket`
/// via `@fieldParentPtr`.  Moving the struct in memory would invalidate those
/// pointers, so every entry lives at a stable heap address.
pub const TlsConnection = struct {
    socket: Socket,
    session: TlsSession,
    host: []const u8,
    port: u16,
    in_use: bool = false,
    broken: bool = false,
    created_at: i64,
    last_used: i64,
    requests_made: u32 = 0,

    const Self = @This();

    /// Marks the connection as in use.
    pub fn acquire(self: *Self) void {
        self.in_use = true;
        self.last_used = milliTimestamp();
    }

    /// Releases the connection back to the pool.
    pub fn release(self: *Self) void {
        self.in_use = false;
        self.last_used = milliTimestamp();
        self.requests_made += 1;
    }

    /// Returns true if the connection is healthy and reusable.
    pub fn isHealthy(self: *const Self, max_idle_ms: i64) bool {
        if (self.in_use) return false;
        if (self.broken) return false;
        if (!self.session.connected) return false;
        const idle_time = milliTimestamp() - self.last_used;
        return idle_time < max_idle_ms;
    }

    /// Marks this connection as broken so it will not be reused.
    pub fn markBroken(self: *Self) void {
        self.broken = true;
    }

    /// Returns true if this connection should be evicted from the pool.
    pub fn shouldEvict(self: *const Self, idle_timeout_ms: i64, max_requests: u32) bool {
        if (self.in_use) return false;
        if (self.broken) return true;
        if (!self.session.connected) return true;
        if (self.requests_made >= max_requests) return true;
        const idle_time = milliTimestamp() - self.last_used;
        return idle_time >= idle_timeout_ms;
    }

    /// Tears down TLS session and closes the underlying socket.
    pub fn close(self: *Self) void {
        self.session.deinit();
        self.socket.close();
    }
};

/// TLS connection pool.
///
/// Manages a set of heap-allocated `TlsConnection` entries keyed by
/// (host, port).  Each entry owns a live TCP socket with a completed TLS
/// handshake, so subsequent HTTPS requests to the same origin skip both
/// TCP connect and TLS negotiation.
pub const TlsPool = struct {
    allocator: Allocator,
    io: Io,
    config: PoolConfig,
    verify_ssl: bool = true,
    connections: std.ArrayListUnmanaged(*TlsConnection) = .empty,
    mutex: Io.Mutex = Io.Mutex.init,
    last_cleanup: i64 = 0,

    const Self = @This();

    /// Creates a TLS connection pool with the given configuration.
    pub fn initWithConfig(allocator: Allocator, io: Io, config: PoolConfig, verify_ssl: bool) Self {
        return .{
            .allocator = allocator,
            .io = io,
            .config = config,
            .verify_ssl = verify_ssl,
        };
    }

    /// Releases all pool resources.
    pub fn deinit(self: *Self) void {
        for (self.connections.items) |entry| {
            entry.close();
            self.allocator.free(entry.host);
            self.allocator.destroy(entry);
        }
        self.connections.deinit(self.allocator);
    }

    /// Gets an idle TLS connection for `(host, port)`, or creates a new one.
    ///
    /// The returned `*TlsConnection` is heap-allocated and marked in-use.
    /// Callers must call `releaseConnection` or `evictConnection` when done.
    pub fn getConnection(self: *Self, host: []const u8, port: u16) !*TlsConnection {
        {
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);

            // Periodic cleanup of stale entries.
            const now = milliTimestamp();
            if (now - self.last_cleanup > self.config.health_check_interval_ms) {
                self.cleanupLocked();
                self.last_cleanup = now;
            }

            for (self.connections.items) |entry| {
                if (std.mem.eql(u8, entry.host, host) and entry.port == port) {
                    if (entry.isHealthy(self.config.idle_timeout_ms) and
                        entry.requests_made < self.config.max_requests_per_connection)
                    {
                        entry.acquire();
                        return entry;
                    }
                }
            }

            if (self.totalCount() >= self.config.max_connections) return PoolError.PoolExhausted;

            var host_count: u32 = 0;
            for (self.connections.items) |entry| {
                if (std.mem.eql(u8, entry.host, host) and entry.port == port) host_count += 1;
            }
            if (host_count >= self.config.max_per_host) return PoolError.PoolExhaustedForHost;
        }

        // Create outside the mutex — DNS, TCP connect, and TLS handshake may block.
        return self.createConnection(host, port);
    }

    /// Creates a new TLS connection: DNS resolve, TCP connect, TLS handshake.
    fn createConnection(self: *Self, host: []const u8, port: u16) !*TlsConnection {
        const host_owned = try self.allocator.dupe(u8, host);
        errdefer self.allocator.free(host_owned);

        const entry = try self.allocator.create(TlsConnection);
        errdefer self.allocator.destroy(entry);

        // Resolve and connect the TCP socket.
        const addr = try Address.resolve(self.io, host, port);
        entry.socket = try Socket.connect(addr, self.io);
        errdefer entry.socket.close();

        // Initialize the TLS session.  The session's handshake method stores
        // internal pointers to entry.socket (via SocketIoReader/Writer stored
        // in entry.session.net_in/net_out), so the entry must already live at
        // its final heap address — which it does, because we created it above.
        const tls_cfg = if (self.verify_ssl) TlsConfig.init(self.allocator) else TlsConfig.insecure(self.allocator);
        entry.session = TlsSession.init(tls_cfg, self.io);
        errdefer entry.session.deinit();

        entry.session.attachSocket(&entry.socket);
        try entry.session.handshake(host);

        const now = milliTimestamp();
        entry.host = host_owned;
        entry.port = port;
        entry.in_use = true;
        entry.broken = false;
        entry.created_at = now;
        entry.last_used = now;
        entry.requests_made = 0;

        // Insert into the pool under the mutex.
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);

        if (self.connections.items.len >= self.config.max_connections) {
            return PoolError.PoolExhausted;
        }
        var recheck_host_count: u32 = 0;
        for (self.connections.items) |c| {
            if (std.mem.eql(u8, c.host, host) and c.port == port) recheck_host_count += 1;
        }
        if (recheck_host_count >= self.config.max_per_host) {
            return PoolError.PoolExhaustedForHost;
        }

        try self.connections.append(self.allocator, entry);
        return entry;
    }

    /// Releases a TLS connection back to the pool for reuse.
    pub fn releaseConnection(self: *Self, entry: *TlsConnection) void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        entry.release();
        const now = milliTimestamp();
        if (now - self.last_cleanup > self.config.health_check_interval_ms) {
            self.cleanupLocked();
            self.last_cleanup = now;
        }
    }

    /// Removes a TLS connection from the pool and frees all its resources.
    pub fn evictConnection(self: *Self, entry: *TlsConnection) void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);

        for (self.connections.items, 0..) |c, i| {
            if (c == entry) {
                _ = self.connections.swapRemove(i);
                break;
            }
        }

        entry.close();
        self.allocator.free(entry.host);
        self.allocator.destroy(entry);
    }

    /// Removes stale/broken TLS connections.
    pub fn cleanup(self: *Self) void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        self.cleanupLocked();
    }

    fn cleanupLocked(self: *Self) void {
        var i: usize = 0;
        while (i < self.connections.items.len) {
            const entry = self.connections.items[i];
            if (entry.shouldEvict(self.config.idle_timeout_ms, self.config.max_requests_per_connection)) {
                entry.close();
                self.allocator.free(entry.host);
                self.allocator.destroy(entry);
                _ = self.connections.swapRemove(i);
            } else {
                i += 1;
            }
        }
    }

    /// Returns the number of active TLS connections.
    pub fn activeCount(self: *const Self) usize {
        var count: usize = 0;
        for (self.connections.items) |entry| {
            if (entry.in_use) count += 1;
        }
        return count;
    }

    /// Returns the total number of TLS connections.
    pub fn totalCount(self: *const Self) usize {
        return self.connections.items.len;
    }

    /// Returns the number of idle TLS connections.
    pub fn idleCount(self: *const Self) usize {
        return self.totalCount() - self.activeCount();
    }

    /// Returns the number of TLS connections for a specific host/port pair.
    pub fn hostConnectionCount(self: *const Self, host: []const u8, port: u16) usize {
        var count: usize = 0;
        for (self.connections.items) |entry| {
            if (std.mem.eql(u8, entry.host, host) and entry.port == port) {
                count += 1;
            }
        }
        return count;
    }

    /// Returns a snapshot of total/active/idle pool counts.
    pub fn stats(self: *const Self) PoolStats {
        const total = self.totalCount();
        const active = self.activeCount();
        return .{ .total = total, .active = active, .idle = total - active };
    }
};

test "ConnectionPool initialization" {
    const allocator = std.testing.allocator;
    var pool_inst = ConnectionPool.init(allocator, std.testing.io);
    defer pool_inst.deinit();

    try std.testing.expectEqual(@as(usize, 0), pool_inst.totalCount());
}

test "ConnectionPool config" {
    const allocator = std.testing.allocator;
    var pool_inst = ConnectionPool.initWithConfig(allocator, std.testing.io, .{
        .max_connections = 50,
        .max_per_host = 10,
    });
    defer pool_inst.deinit();

    try std.testing.expectEqual(@as(u32, 50), pool_inst.config.max_connections);
    try std.testing.expectEqual(@as(u32, 10), pool_inst.config.max_per_host);
}

test "Connection health check" {
    const io = std.testing.io;
    const listen_addr = Address{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } };
    var listener = try @import("../net/socket.zig").TcpListener.init(listen_addr, io);
    defer listener.deinit();
    const bound_addr = listener.getLocalAddress();

    var conn = Connection{
        .socket = try Socket.connect(bound_addr, io),
        .host = "localhost",
        .port = 8080,
        .created_at = milliTimestamp(),
        .last_used = milliTimestamp(),
    };
    defer conn.socket.close();

    try std.testing.expect(conn.isHealthy(60_000));

    conn.in_use = true;
    try std.testing.expect(!conn.isHealthy(60_000));
}

test "ConnectionPool stats helpers" {
    const allocator = std.testing.allocator;
    var pool_inst = ConnectionPool.init(allocator, std.testing.io);
    defer pool_inst.deinit();

    const s = pool_inst.stats();
    try std.testing.expectEqual(@as(usize, 0), s.total);
    try std.testing.expectEqual(@as(usize, 0), s.active);
    try std.testing.expectEqual(@as(usize, 0), s.idle);
    try std.testing.expectEqual(@as(usize, 0), pool_inst.hostConnectionCount("example.com", 443));
}

test "ConnectionPool mutex prevents data races" {
    const allocator = std.testing.allocator;
    var pool_inst = ConnectionPool.init(allocator, std.testing.io);
    defer pool_inst.deinit();

    // Verify that mutex-protected methods can be called from the same thread
    // without deadlocking (basic smoke test for the mutex wiring).
    pool_inst.cleanup();
    const s = pool_inst.stats();
    try std.testing.expectEqual(@as(usize, 0), s.total);
}

test "TlsConnection health check basics" {
    const now = milliTimestamp();
    // We cannot construct a real TlsConnection without a network peer, so
    // test the health-check logic by inspecting flag combinations on a
    // zero-initialized stub (socket/session fields are not touched by the
    // health predicates).
    var entry: TlsConnection = undefined;
    entry.in_use = false;
    entry.broken = false;
    entry.session.connected = true;
    entry.last_used = now;
    entry.requests_made = 0;
    entry.created_at = now;

    // Healthy idle connection.
    try std.testing.expect(entry.isHealthy(60_000));

    // In-use connection is not considered healthy (for pool reuse).
    entry.in_use = true;
    try std.testing.expect(!entry.isHealthy(60_000));
    entry.in_use = false;

    // Broken connection.
    entry.broken = true;
    try std.testing.expect(!entry.isHealthy(60_000));
    entry.broken = false;

    // Disconnected TLS session.
    entry.session.connected = false;
    try std.testing.expect(!entry.isHealthy(60_000));
}

test "TlsPool initialization and stats" {
    const allocator = std.testing.allocator;
    var tls_pool = TlsPool.initWithConfig(allocator, std.testing.io, .{}, true);
    defer tls_pool.deinit();

    const s = tls_pool.stats();
    try std.testing.expectEqual(@as(usize, 0), s.total);
    try std.testing.expectEqual(@as(usize, 0), s.active);
    try std.testing.expectEqual(@as(usize, 0), s.idle);
    try std.testing.expectEqual(@as(usize, 0), tls_pool.hostConnectionCount("example.com", 443));
}

test "TlsPool cleanup on empty pool" {
    const allocator = std.testing.allocator;
    var tls_pool = TlsPool.initWithConfig(allocator, std.testing.io, .{}, true);
    defer tls_pool.deinit();

    // Should not panic on an empty pool.
    tls_pool.cleanup();
    try std.testing.expectEqual(@as(usize, 0), tls_pool.totalCount());
}
