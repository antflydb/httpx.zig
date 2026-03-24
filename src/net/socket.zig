//! Cross-Platform Socket Abstraction for httpx.zig
//!
//! Pure-Zig networking via std.Io (no libc dependency):
//!
//! - TCP client and server socket operations via std.Io.net
//! - UDP datagram sockets
//! - Configurable socket options (via posix.setsockopt)
//! - Io.Reader/Io.Writer adapters for TLS integration

const std = @import("std");
const posix = std.posix;
const Io = std.Io;
const net = Io.net;
const Allocator = std.mem.Allocator;
const builtin = @import("builtin");

const is_windows = builtin.os.tag == .windows;

/// Network address type (std.Io.net.IpAddress).
pub const Address = net.IpAddress;

/// TCP socket abstraction backed by std.Io.net.
pub const Socket = struct {
    handle: net.Socket.Handle,
    io: Io,

    const Self = @This();

    pub const AcceptResult = struct {
        socket: Socket,
        addr: Address,
    };

    /// Connects to the given address and returns a connected TCP socket.
    pub fn connect(addr: Address, io: Io) !Self {
        const stream = try addr.connect(io, .{ .mode = .stream });
        return .{ .handle = stream.socket.handle, .io = io };
    }

    /// Creates a socket from a raw handle (e.g. from accept).
    pub fn fromHandle(handle: net.Socket.Handle, io: Io) Self {
        return .{ .handle = handle, .io = io };
    }

    /// Closes the socket.
    pub fn close(self: *Self) void {
        self.io.vtable.netClose(self.io.userdata, @ptrCast((&self.handle)[0..1]));
    }

    /// Sends data, returning the number of bytes written.
    pub fn send(self: *Self, data: []const u8) !usize {
        return self.io.vtable.netWrite(self.io.userdata, self.handle, "", &.{data}, 1) catch return error.SendFailed;
    }

    /// Sends all data, blocking until complete.
    pub fn sendAll(self: *Self, data: []const u8) !void {
        var sent: usize = 0;
        while (sent < data.len) {
            sent += try self.send(data[sent..]);
        }
    }

    /// Receives data into the buffer, returning bytes received (0 = EOF).
    pub fn recv(self: *Self, buffer: []u8) !usize {
        var bufs = [_][]u8{buffer};
        return self.io.vtable.netRead(self.io.userdata, self.handle, &bufs) catch return error.RecvFailed;
    }

    /// Enables or disables TCP_NODELAY (Nagle's algorithm).
    pub fn setNoDelay(self: *Self, enable: bool) !void {
        const value: u32 = if (enable) 1 else 0;
        try posix.setsockopt(self.handle, posix.IPPROTO.TCP, posix.TCP.NODELAY, std.mem.asBytes(&value));
    }

    /// Sets the receive timeout in milliseconds.
    pub fn setRecvTimeout(self: *Self, ms: u64) !void {
        try self.setTimeout(posix.SO.RCVTIMEO, ms);
    }

    /// Sets the send timeout in milliseconds.
    pub fn setSendTimeout(self: *Self, ms: u64) !void {
        try self.setTimeout(posix.SO.SNDTIMEO, ms);
    }

    fn setTimeout(self: *Self, opt: u32, ms: u64) !void {
        if (is_windows) {
            const value_ms: u32 = @intCast(@min(ms, @as(u64, std.math.maxInt(u32))));
            try posix.setsockopt(self.handle, posix.SOL.SOCKET, opt, std.mem.asBytes(&value_ms));
        } else {
            const tv = posix.timeval{
                .sec = @intCast(ms / 1000),
                .usec = @intCast((ms % 1000) * 1000),
            };
            try posix.setsockopt(self.handle, posix.SOL.SOCKET, opt, std.mem.asBytes(&tv));
        }
    }

    /// Enables or disables keep-alive probes.
    pub fn setKeepAlive(self: *Self, enable: bool) !void {
        const value: u32 = if (enable) 1 else 0;
        try posix.setsockopt(self.handle, posix.SOL.SOCKET, posix.SO.KEEPALIVE, std.mem.asBytes(&value));
    }

    /// Returns a reader interface for the socket.
    pub fn reader(self: *Self) std.io.AnyReader {
        return .{
            .context = @ptrCast(self),
            .readFn = struct {
                fn read(ctx: *const anyopaque, buffer: []u8) !usize {
                    const s: *Socket = @ptrCast(@constCast(ctx));
                    return s.recv(buffer) catch |err| switch (err) {
                        error.WouldBlock => 0,
                        else => err,
                    };
                }
            }.read,
        };
    }

    /// Returns a writer interface for the socket.
    pub fn writer(self: *Self) std.io.AnyWriter {
        return .{
            .context = @ptrCast(self),
            .writeFn = struct {
                fn write(ctx: *const anyopaque, data: []const u8) !usize {
                    const s: *Socket = @ptrCast(@constCast(ctx));
                    return s.send(data);
                }
            }.write,
        };
    }
};

/// Shared Io.Reader VTable helpers for custom reader adapters.
/// These generic implementations call through the vtable's `readVec` and
/// can be reused by any adapter that only needs to provide `readVec`.
pub const IoReaderHelpers = struct {
    pub fn stream(r: *Io.Reader, w: *Io.Writer, limit: Io.Limit) Io.Reader.StreamError!usize {
        var total: usize = 0;
        const max_limit = limit.toInt() orelse std.math.maxInt(usize);

        while (total < max_limit) {
            const max_to_read = @min(r.buffer.len, max_limit - total);
            var iov = [_][]u8{r.buffer[0..max_to_read]};
            const n = r.vtable.readVec(r, &iov) catch |err| switch (err) {
                error.EndOfStream => break,
                else => return err,
            };
            if (n == 0) break;

            try w.writeAll(r.buffer[0..n]);
            total += n;
        }

        return total;
    }

    pub fn discard(r: *Io.Reader, limit: Io.Limit) error{ EndOfStream, ReadFailed }!usize {
        var total: usize = 0;
        const max_limit = limit.toInt() orelse std.math.maxInt(usize);

        while (total < max_limit) {
            const max_to_read = @min(r.buffer.len, max_limit - total);
            var iov = [_][]u8{r.buffer[0..max_to_read]};
            const n = r.vtable.readVec(r, &iov) catch |err| switch (err) {
                error.EndOfStream => break,
                else => return err,
            };
            if (n == 0) break;
            total += n;
        }

        return total;
    }

    pub fn rebase(_: *Io.Reader, _: usize) Io.Reader.RebaseError!void {}
};

/// Adapter that exposes a `std.Io.Reader` backed by a connected `Socket`.
///
/// This is primarily used to integrate with `std.crypto.tls.Client`.
pub const SocketIoReader = struct {
    socket: *Socket,
    reader_iface: Io.Reader,

    pub fn init(socket: *Socket, buffer: []u8) SocketIoReader {
        return .{
            .socket = socket,
            .reader_iface = .{
                .vtable = &vtable,
                .buffer = buffer,
                .seek = 0,
                .end = 0,
            },
        };
    }

    fn parent(r: *Io.Reader) *SocketIoReader {
        return @fieldParentPtr("reader_iface", r);
    }

    fn readVec(r: *Io.Reader, bufs: [][]u8) Io.Reader.Error!usize {
        const p = parent(r);
        if (bufs.len == 0) return 0;
        const buf = bufs[0];
        const n = p.socket.recv(buf) catch return error.ReadFailed;
        if (n == 0) return error.EndOfStream;
        return n;
    }

    const vtable: Io.Reader.VTable = .{
        .stream = IoReaderHelpers.stream,
        .discard = IoReaderHelpers.discard,
        .readVec = readVec,
        .rebase = IoReaderHelpers.rebase,
    };
};

/// Adapter that exposes a `std.Io.Writer` backed by a connected `Socket`.
///
/// This is primarily used to integrate with `std.crypto.tls.Client`.
pub const SocketIoWriter = struct {
    socket: *Socket,
    writer_iface: Io.Writer,

    pub fn init(socket: *Socket, buffer: []u8) SocketIoWriter {
        return .{
            .socket = socket,
            .writer_iface = .{
                .vtable = &vtable,
                .buffer = buffer,
                .end = 0,
            },
        };
    }

    fn parent(w: *Io.Writer) *SocketIoWriter {
        return @fieldParentPtr("writer_iface", w);
    }

    fn drain(w: *Io.Writer, bufs: []const []const u8, start_index: usize) Io.Writer.Error!usize {
        const p = parent(w);
        var i: usize = start_index;
        while (i < bufs.len and bufs[i].len == 0) : (i += 1) {}
        if (i >= bufs.len) return 0;

        const n = p.socket.send(bufs[i]) catch return error.WriteFailed;
        return n;
    }

    fn sendFile(w: *Io.Writer, file_reader: *Io.File.Reader, limit: Io.Limit) Io.Writer.FileError!usize {
        const p = parent(w);

        var total: usize = 0;
        const max_limit = limit.toInt() orelse std.math.maxInt(usize);
        while (total < max_limit) {
            const remaining = max_limit - total;
            const chunk_len = @min(w.buffer.len, remaining);
            if (chunk_len == 0) break;

            const n_read = file_reader.file.readStreaming(file_reader.io, &.{w.buffer[0..chunk_len]}) catch return error.ReadFailed;
            if (n_read == 0) break;

            p.socket.sendAll(w.buffer[0..n_read]) catch return error.WriteFailed;
            total += n_read;
        }

        return total;
    }

    fn flush(_: *Io.Writer) Io.Writer.Error!void {}

    fn rebase(_: *Io.Writer, _: usize, _: usize) Io.Writer.Error!void {}

    const vtable: Io.Writer.VTable = .{
        .drain = drain,
        .sendFile = sendFile,
        .flush = flush,
        .rebase = rebase,
    };
};

/// TCP listener for accepting incoming connections.
pub const TcpListener = struct {
    server: net.Server,
    io: Io,

    const Self = @This();

    /// Creates and binds a TCP listener to the address.
    pub fn init(addr: Address, io: Io) !Self {
        return initWithOptions(addr, io, .{ .reuse_address = true });
    }

    /// Creates and binds with explicit options.
    pub fn initWithOptions(addr: Address, io: Io, options: Address.ListenOptions) !Self {
        const server = try addr.listen(io, options);
        return .{ .server = server, .io = io };
    }

    /// Closes the listener.
    pub fn deinit(self: *Self) void {
        self.server.deinit(self.io);
    }

    /// Accepts an incoming connection.
    pub fn accept(self: *Self) !Socket.AcceptResult {
        const stream = try self.server.accept(self.io);
        return .{
            .socket = Socket.fromHandle(stream.socket.handle, self.io),
            .addr = stream.socket.address,
        };
    }

    /// Returns the local address the listener is bound to.
    pub fn getLocalAddress(self: *Self) Address {
        return self.server.socket.address;
    }
};

/// UDP datagram socket abstraction backed by std.Io.net.
pub const UdpSocket = struct {
    socket: net.Socket,
    io: Io,

    const Self = @This();

    /// Creates a UDP socket bound to the given address.
    pub fn bind(addr: Address, io: Io) !Self {
        const socket = try addr.bind(io, .{ .mode = .dgram });
        return .{ .socket = socket, .io = io };
    }

    /// Closes the socket.
    pub fn close(self: *Self) void {
        self.socket.close(self.io);
    }

    /// Sends a datagram to a specific address.
    pub fn sendTo(self: *Self, dest: Address, data: []const u8) !usize {
        self.socket.send(self.io, &dest, data) catch return error.SendFailed;
        return data.len;
    }

    /// Receives a datagram and returns the source address.
    pub fn recvFrom(self: *Self, buffer: []u8) !struct { n: usize, addr: Address } {
        const msg = self.socket.receive(self.io, buffer) catch return error.RecvFailed;
        return .{ .n = msg.data.len, .addr = msg.from };
    }
};

test "Socket connect and close" {
    const io = std.testing.io;

    // Listen on a random port
    const listen_addr = Address{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } };
    var listener = try TcpListener.init(listen_addr, io);
    defer listener.deinit();

    const bound_addr = listener.getLocalAddress();
    try std.testing.expect(bound_addr.getPort() != 0);

    // Connect
    var socket = try Socket.connect(bound_addr, io);
    defer socket.close();
}

test "TcpListener accept" {
    const io = std.testing.io;

    const listen_addr = Address{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } };
    var listener = try TcpListener.init(listen_addr, io);
    defer listener.deinit();

    const bound_addr = listener.getLocalAddress();

    // Connect client
    var client = try Socket.connect(bound_addr, io);
    defer client.close();

    // Accept server side
    var result = try listener.accept();
    defer result.socket.close();
}

test "UdpSocket send/recv localhost" {
    const io = std.testing.io;

    const bind_addr = Address{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } };
    var recv_sock = try UdpSocket.bind(bind_addr, io);
    defer recv_sock.close();

    const recv_addr = recv_sock.socket.address;

    var send_sock = try UdpSocket.bind(bind_addr, io);
    defer send_sock.close();

    const msg = "ping";
    _ = try send_sock.sendTo(recv_addr, msg);

    var buf: [32]u8 = undefined;
    const got = try recv_sock.recvFrom(&buf);
    try std.testing.expectEqualStrings(msg, buf[0..got.n]);
}
