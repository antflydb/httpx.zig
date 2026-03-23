//! HTTP Connection Pool for httpx.zig
//!
//! Provides connection pooling for HTTP clients:
//!
//! - Reusable TCP connections with keep-alive
//! - Per-host connection limits
//! - Automatic connection health checking
//! - Idle connection timeout and cleanup

const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;

const Socket = @import("../net/socket.zig").Socket;
const Address = @import("../net/socket.zig").Address;

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
    created_at: i64,
    last_used: i64,
    requests_made: u32 = 0,

    const Self = @This();

    /// Marks the connection as in use.
    pub fn acquire(self: *Self) void {
        self.in_use = true;
        self.last_used = std.time.milliTimestamp();
    }

    /// Releases the connection back to the pool.
    pub fn release(self: *Self) void {
        self.in_use = false;
        self.last_used = std.time.milliTimestamp();
        self.requests_made += 1;
    }

    /// Returns true if the connection is healthy and reusable.
    pub fn isHealthy(self: *const Self, max_idle_ms: i64) bool {
        if (self.in_use) return false;
        const idle_time = std.time.milliTimestamp() - self.last_used;
        return idle_time < max_idle_ms;
    }

    /// Returns true if this connection should be evicted from the pool.
    pub fn shouldEvict(self: *const Self, idle_timeout_ms: i64, max_requests_per_connection: u32) bool {
        if (self.in_use) return false;
        if (self.requests_made >= max_requests_per_connection) return true;
        const idle_time = std.time.milliTimestamp() - self.last_used;
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
    mutex: std.Thread.Mutex = .{},

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
            self.mutex.lock();
            defer self.mutex.unlock();

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

        const now = std.time.milliTimestamp();

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

        self.mutex.lock();
        defer self.mutex.unlock();
        try self.connections.append(self.allocator, conn);

        return conn;
    }

    /// Releases a connection back to the pool.
    pub fn releaseConnection(self: *Self, conn: *Connection) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        conn.release();
    }

    /// Removes idle connections that have exceeded the timeout.
    pub fn cleanup(self: *Self) void {
        self.mutex.lock();
        defer self.mutex.unlock();
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
        .created_at = std.time.milliTimestamp(),
        .last_used = std.time.milliTimestamp(),
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
