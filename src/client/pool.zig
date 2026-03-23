//! HTTP Connection Pool for httpx.zig
//!
//! Provides connection pooling for HTTP clients:
//!
//! - Reusable TCP and TLS connections with keep-alive
//! - Per-host connection limits
//! - Automatic connection health checking
//! - Idle connection timeout and cleanup
//!
//! Both `ConnectionPool` (plain TCP) and `TlsPool` (TCP + TLS) are
//! instantiations of `GenericPool`, which handles all shared pool logic.

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

// ---------------------------------------------------------------------------
// Connection entry types
// ---------------------------------------------------------------------------

/// Pooled TCP connection.
pub const Connection = struct {
    socket: Socket,
    host: []const u8,
    port: u16,
    in_use: bool = false,
    broken: bool = false,
    created_at: i64,
    last_used: i64,
    requests_made: u32 = 0,

    pub fn acquire(self: *Connection, now: i64) void {
        self.in_use = true;
        self.last_used = now;
    }

    pub fn release(self: *Connection, now: i64) void {
        self.in_use = false;
        self.last_used = now;
        self.requests_made += 1;
    }

    pub fn isHealthy(self: *const Connection, max_idle_ms: i64, now: i64) bool {
        if (self.in_use) return false;
        if (self.broken) return false;
        return (now - self.last_used) < max_idle_ms;
    }

    pub fn markBroken(self: *Connection) void {
        self.broken = true;
    }

    pub fn shouldEvict(self: *const Connection, idle_timeout_ms: i64, max_requests: u32, now: i64) bool {
        if (self.in_use) return false;
        if (self.broken) return true;
        if (self.requests_made >= max_requests) return true;
        return (now - self.last_used) >= idle_timeout_ms;
    }

    pub fn close(self: *Connection) void {
        self.socket.close();
    }

    /// Creates a new TCP connection (DNS resolve + TCP connect).
    pub fn createNew(allocator: Allocator, io: Io, host: []const u8, port: u16, _: void) !*Connection {
        const host_owned = try allocator.dupe(u8, host);
        errdefer allocator.free(host_owned);

        const addr = try Address.resolve(io, host, port);
        var socket = try Socket.connect(addr, io);
        errdefer socket.close();

        const now = milliTimestamp();
        const conn = try allocator.create(Connection);
        conn.* = .{
            .socket = socket,
            .host = host_owned,
            .port = port,
            .in_use = true,
            .created_at = now,
            .last_used = now,
        };
        return conn;
    }
};

/// Context passed to `TlsConnection.createNew` for TLS-specific configuration.
pub const TlsPoolContext = struct {
    verify_ssl: bool,
};

/// Pooled TLS connection bundle.
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

    pub fn acquire(self: *TlsConnection, now: i64) void {
        self.in_use = true;
        self.last_used = now;
    }

    pub fn release(self: *TlsConnection, now: i64) void {
        self.in_use = false;
        self.last_used = now;
        self.requests_made += 1;
    }

    pub fn isHealthy(self: *const TlsConnection, max_idle_ms: i64, now: i64) bool {
        if (self.in_use) return false;
        if (self.broken) return false;
        if (!self.session.connected) return false;
        return (now - self.last_used) < max_idle_ms;
    }

    pub fn markBroken(self: *TlsConnection) void {
        self.broken = true;
    }

    pub fn shouldEvict(self: *const TlsConnection, idle_timeout_ms: i64, max_requests: u32, now: i64) bool {
        if (self.in_use) return false;
        if (self.broken) return true;
        if (!self.session.connected) return true;
        if (self.requests_made >= max_requests) return true;
        return (now - self.last_used) >= idle_timeout_ms;
    }

    pub fn close(self: *TlsConnection) void {
        self.session.deinit();
        self.socket.close();
    }

    /// Creates a new TLS connection (DNS resolve + TCP connect + TLS handshake).
    pub fn createNew(allocator: Allocator, io: Io, host: []const u8, port: u16, ctx: TlsPoolContext) !*TlsConnection {
        const host_owned = try allocator.dupe(u8, host);
        errdefer allocator.free(host_owned);

        const entry = try allocator.create(TlsConnection);
        errdefer allocator.destroy(entry);

        // Resolve and connect the TCP socket.
        const addr = try Address.resolve(io, host, port);
        entry.socket = try Socket.connect(addr, io);
        errdefer entry.socket.close();

        // Initialize the TLS session.  The session stores internal pointers to
        // entry.socket (via SocketIoReader/Writer), so the entry must already
        // live at its final heap address — which it does.
        const tls_cfg = if (ctx.verify_ssl) TlsConfig.init(allocator) else TlsConfig.insecure(allocator);
        entry.session = TlsSession.init(tls_cfg, io);
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

        return entry;
    }
};

// ---------------------------------------------------------------------------
// Pool configuration and stats
// ---------------------------------------------------------------------------

/// Connection pool configuration.
pub const PoolConfig = struct {
    max_connections: u32 = 20,
    max_per_host: u32 = 5,
    idle_timeout_ms: i64 = 60_000,
    max_requests_per_connection: u32 = 1000,
    health_check_interval_ms: i64 = 30_000,
};

/// Snapshot statistics for a connection pool.
pub const PoolStats = struct {
    total: usize,
    active: usize,
    idle: usize,
};

// ---------------------------------------------------------------------------
// Generic connection pool
// ---------------------------------------------------------------------------

/// Generic connection pool parameterized on entry type and creation context.
///
/// `Entry` must provide:
///   - Fields: `host: []const u8`, `port: u16`, `in_use: bool`, `requests_made: u32`
///   - Methods: `acquire(now)`, `release(now)`, `isHealthy(ms, now)`,
///     `shouldEvict(ms, max, now)`, `close()`, `markBroken()`
///   - Class method: `createNew(allocator, io, host, port, context) !*Entry`
///
/// `Context` is an arbitrary type forwarded to `Entry.createNew`.
/// Use `void` when no extra context is needed (e.g. plain TCP).
pub fn GenericPool(comptime Entry: type, comptime Context: type) type {
    return struct {
        allocator: Allocator,
        io: Io,
        config: PoolConfig,
        context: Context,
        connections: std.ArrayListUnmanaged(*Entry) = .empty,
        mutex: Io.Mutex = Io.Mutex.init,
        last_cleanup: i64 = 0,

        const Self = @This();

        /// Creates a new pool with default configuration.
        pub fn init(allocator: Allocator, io: Io, context: Context) Self {
            return initWithConfig(allocator, io, .{}, context);
        }

        /// Creates a pool with custom configuration.
        pub fn initWithConfig(allocator: Allocator, io: Io, config: PoolConfig, context: Context) Self {
            return .{
                .allocator = allocator,
                .io = io,
                .config = config,
                .context = context,
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

        /// Gets an idle connection for `(host, port)`, or creates a new one.
        ///
        /// The returned pointer is heap-allocated and marked in-use.
        /// Callers must call `releaseConnection` or `evictConnection` when done.
        pub fn getConnection(self: *Self, host: []const u8, port: u16) !*Entry {
            {
                self.mutex.lockUncancelable(self.io);
                defer self.mutex.unlock(self.io);

                // Periodic cleanup: evict stale/broken connections.
                const now = milliTimestamp();
                if (now - self.last_cleanup > self.config.health_check_interval_ms) {
                    self.cleanupLocked(now);
                    self.last_cleanup = now;
                }

                for (self.connections.items) |entry| {
                    if (std.mem.eql(u8, entry.host, host) and entry.port == port) {
                        if (entry.isHealthy(self.config.idle_timeout_ms, now) and
                            entry.requests_made < self.config.max_requests_per_connection)
                        {
                            entry.acquire(now);
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

            // Create outside the mutex — DNS, TCP connect (and TLS handshake) may block.
            return self.createConnection(host, port);
        }

        /// Creates a new connection via `Entry.createNew`, then inserts it
        /// into the pool after re-checking limits under the mutex.
        fn createConnection(self: *Self, host: []const u8, port: u16) !*Entry {
            const entry = try Entry.createNew(self.allocator, self.io, host, port, self.context);
            errdefer {
                entry.close();
                self.allocator.free(entry.host);
                self.allocator.destroy(entry);
            }

            // Insert into the pool under the mutex.
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);

            // Re-check limits — another fiber may have raced and filled the
            // pool while we were connecting.
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

        /// Releases a connection back to the pool for reuse.
        pub fn releaseConnection(self: *Self, entry: *Entry) void {
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);
            const now = milliTimestamp();
            entry.release(now);
            // Opportunistic cleanup on release.
            if (now - self.last_cleanup > self.config.health_check_interval_ms) {
                self.cleanupLocked(now);
                self.last_cleanup = now;
            }
        }

        /// Removes a connection from the pool and frees all its resources.
        /// Use this when a network error occurs instead of releasing.
        pub fn evictConnection(self: *Self, entry: *Entry) void {
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

        /// Removes idle/broken connections that should be evicted.
        pub fn cleanup(self: *Self) void {
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);
            self.cleanupLocked(milliTimestamp());
        }

        fn cleanupLocked(self: *Self, now: i64) void {
            var i: usize = 0;
            while (i < self.connections.items.len) {
                const entry = self.connections.items[i];
                if (entry.shouldEvict(self.config.idle_timeout_ms, self.config.max_requests_per_connection, now)) {
                    entry.close();
                    self.allocator.free(entry.host);
                    self.allocator.destroy(entry);
                    _ = self.connections.swapRemove(i);
                } else {
                    i += 1;
                }
            }
        }

        /// Returns the number of in-use connections.
        pub fn activeCount(self: *const Self) usize {
            var count: usize = 0;
            for (self.connections.items) |entry| {
                if (entry.in_use) count += 1;
            }
            return count;
        }

        /// Returns the total number of connections (active + idle).
        pub fn totalCount(self: *const Self) usize {
            return self.connections.items.len;
        }

        /// Returns the number of idle connections.
        pub fn idleCount(self: *const Self) usize {
            return self.totalCount() - self.activeCount();
        }

        /// Returns the number of connections for a specific host/port pair.
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
}

// ---------------------------------------------------------------------------
// Public type aliases
// ---------------------------------------------------------------------------

/// HTTP connection pool (plain TCP).
pub const ConnectionPool = GenericPool(Connection, void);

/// HTTPS connection pool (TCP + TLS).
pub const TlsPool = GenericPool(TlsConnection, TlsPoolContext);

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "ConnectionPool initialization" {
    const allocator = std.testing.allocator;
    var pool_inst = ConnectionPool.init(allocator, std.testing.io, {});
    defer pool_inst.deinit();

    try std.testing.expectEqual(@as(usize, 0), pool_inst.totalCount());
}

test "ConnectionPool config" {
    const allocator = std.testing.allocator;
    var pool_inst = ConnectionPool.initWithConfig(allocator, std.testing.io, .{
        .max_connections = 50,
        .max_per_host = 10,
    }, {});
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

    const now = milliTimestamp();
    var conn = Connection{
        .socket = try Socket.connect(bound_addr, io),
        .host = "localhost",
        .port = 8080,
        .created_at = now,
        .last_used = now,
    };
    defer conn.socket.close();

    try std.testing.expect(conn.isHealthy(60_000, now));

    conn.in_use = true;
    try std.testing.expect(!conn.isHealthy(60_000, now));
}

test "ConnectionPool stats helpers" {
    const allocator = std.testing.allocator;
    var pool_inst = ConnectionPool.init(allocator, std.testing.io, {});
    defer pool_inst.deinit();

    const s = pool_inst.stats();
    try std.testing.expectEqual(@as(usize, 0), s.total);
    try std.testing.expectEqual(@as(usize, 0), s.active);
    try std.testing.expectEqual(@as(usize, 0), s.idle);
    try std.testing.expectEqual(@as(usize, 0), pool_inst.hostConnectionCount("example.com", 443));
}

test "ConnectionPool mutex prevents data races" {
    const allocator = std.testing.allocator;
    var pool_inst = ConnectionPool.init(allocator, std.testing.io, {});
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
    try std.testing.expect(entry.isHealthy(60_000, now));

    // In-use connection is not considered healthy (for pool reuse).
    entry.in_use = true;
    try std.testing.expect(!entry.isHealthy(60_000, now));
    entry.in_use = false;

    // Broken connection.
    entry.broken = true;
    try std.testing.expect(!entry.isHealthy(60_000, now));
    entry.broken = false;

    // Disconnected TLS session.
    entry.session.connected = false;
    try std.testing.expect(!entry.isHealthy(60_000, now));
}

test "TlsPool initialization and stats" {
    const allocator = std.testing.allocator;
    var tls_pool = TlsPool.initWithConfig(allocator, std.testing.io, .{}, .{ .verify_ssl = true });
    defer tls_pool.deinit();

    const s = tls_pool.stats();
    try std.testing.expectEqual(@as(usize, 0), s.total);
    try std.testing.expectEqual(@as(usize, 0), s.active);
    try std.testing.expectEqual(@as(usize, 0), s.idle);
    try std.testing.expectEqual(@as(usize, 0), tls_pool.hostConnectionCount("example.com", 443));
}

test "TlsPool cleanup on empty pool" {
    const allocator = std.testing.allocator;
    var tls_pool = TlsPool.initWithConfig(allocator, std.testing.io, .{}, .{ .verify_ssl = true });
    defer tls_pool.deinit();

    // Should not panic on an empty pool.
    tls_pool.cleanup();
    try std.testing.expectEqual(@as(usize, 0), tls_pool.totalCount());
}
