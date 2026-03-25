//! HTTP/2 Connection Layer for httpx.zig
//!
//! Implements the HTTP/2 connection state machine (RFC 7540) on top of existing
//! protocol primitives (HPACK, stream management, frame headers, SETTINGS).
//!
//! Features:
//! - Connection preface exchange (client and server)
//! - SETTINGS handshake with ACK tracking
//! - Frame I/O: read/write frames over any reader/writer
//! - PING echo, GOAWAY handling, WINDOW_UPDATE flow control
//! - HEADERS frame splitting into CONTINUATION when exceeding MAX_FRAME_SIZE
//! - CONTINUATION frame reassembly on receive
//! - Pseudo-header construction for HTTP/2 requests and responses

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const Io = std.Io;

const http = @import("http.zig");
const stream_mod = @import("stream.zig");
const hpack = @import("hpack.zig");
const types = @import("../core/types.zig");

const Http2FrameType = http.Http2FrameType;
const Http2FrameHeader = http.Http2FrameHeader;
const Http2ErrorCode = http.Http2ErrorCode;
const Http2Settings = types.Http2Settings;
const StreamManager = stream_mod.StreamManager;
const Stream = stream_mod.Stream;
const StreamPriority = stream_mod.StreamPriority;

/// A received HTTP/2 frame (header + payload).
pub const Frame = struct {
    header: Http2FrameHeader,
    payload: []u8,

    pub fn deinit(self: *Frame, allocator: Allocator) void {
        if (self.payload.len > 0) allocator.free(self.payload);
    }
};

/// HTTP/2 connection state machine.
///
/// Owns a `StreamManager` and drives frame I/O over an arbitrary
/// reader/writer pair (plain TCP socket or TLS session).
/// Reader must have `read(buf: []u8) !usize` or `recv(buf: []u8) !usize`.
/// Writer must have `writeAll(data: []const u8) !void`.
pub const H2Connection = struct {
    allocator: Allocator,
    io: Io,
    stream_manager: StreamManager,
    local_settings: Http2Settings,
    peer_settings: Http2Settings,
    is_server: bool,
    goaway_sent: bool = false,
    goaway_received: bool = false,
    last_peer_stream_id: u31 = 0,

    /// Serializes frame writes so multiple fibers can safely share one connection.
    write_mutex: Io.Mutex = Io.Mutex.init,

    // Reassembly buffer for CONTINUATION frames.
    continuation_stream_id: ?u31 = null,
    continuation_buf: std.ArrayListUnmanaged(u8) = .empty,
    continuation_flags: u8 = 0,

    const Self = @This();

    // -- Frame flag constants (RFC 7540 §6) --
    pub const FLAG_ACK: u8 = 0x01;
    pub const FLAG_END_STREAM: u8 = 0x01;
    pub const FLAG_END_HEADERS: u8 = 0x04;
    pub const FLAG_PADDED: u8 = 0x08;
    pub const FLAG_PRIORITY: u8 = 0x20;

    /// Creates a client-side HTTP/2 connection.
    pub fn initClient(allocator: Allocator, io: Io) Self {
        return .{
            .allocator = allocator,
            .io = io,
            .stream_manager = StreamManager.init(allocator, true),
            .local_settings = .{},
            .peer_settings = .{},
            .is_server = false,
        };
    }

    /// Creates a server-side HTTP/2 connection.
    pub fn initServer(allocator: Allocator, io: Io) Self {
        return .{
            .allocator = allocator,
            .io = io,
            .stream_manager = StreamManager.init(allocator, false),
            .local_settings = .{},
            .peer_settings = .{},
            .is_server = true,
        };
    }

    pub fn deinit(self: *Self) void {
        self.stream_manager.deinit();
        self.continuation_buf.deinit(self.allocator);
    }

    // ---------------------------------------------------------------
    // Connection Preface (RFC 7540 §3.5)
    // ---------------------------------------------------------------

    /// Client: sends the connection preface (magic + SETTINGS).
    pub fn sendClientPreface(self: *Self, writer: anytype) !void {
        try writer.writeAll(http.HTTP2_PREFACE);
        try self.sendSettings(writer);
    }

    /// Server: reads and validates the 24-byte client preface magic.
    /// The caller must then read the client's SETTINGS frame via `readFrame`.
    pub fn readClientPreface(self: *Self, reader: anytype) !void {
        _ = self;
        var buf: [24]u8 = undefined;
        try readExact(reader, &buf);
        if (!mem.eql(u8, &buf, http.HTTP2_PREFACE)) return error.ProtocolError;
    }

    // ---------------------------------------------------------------
    // SETTINGS (RFC 7540 §6.5)
    // ---------------------------------------------------------------

    /// Sends our local SETTINGS frame.
    pub fn sendSettings(self: *Self, writer: anytype) !void {
        var payload_buf = std.ArrayListUnmanaged(u8).empty;
        defer payload_buf.deinit(self.allocator);
        try http.encodeSettingsPayload(self.local_settings, self.allocator, &payload_buf);
        try self.writeFrame(writer, .settings, 0, 0, payload_buf.items);
    }

    /// Sends a SETTINGS ACK (empty SETTINGS with ACK flag).
    pub fn sendSettingsAck(self: *Self, writer: anytype) !void {
        try self.writeFrame(writer, .settings, FLAG_ACK, 0, &.{});
    }

    /// Applies a received SETTINGS payload to `peer_settings`.
    /// Updates stream windows if INITIAL_WINDOW_SIZE changed.
    pub fn applyPeerSettings(self: *Self, payload: []const u8) !void {
        const old_window = self.peer_settings.initial_window_size;
        try http.applySettingsPayload(&self.peer_settings, payload);
        const new_window = self.peer_settings.initial_window_size;
        if (old_window != new_window) {
            try self.stream_manager.applyInitialWindowSizeChange(old_window, new_window);
        }
        self.stream_manager.max_concurrent_streams = self.peer_settings.max_concurrent_streams;
    }

    // ---------------------------------------------------------------
    // Frame I/O
    // ---------------------------------------------------------------

    /// Reads one HTTP/2 frame. Handles CONTINUATION reassembly.
    /// Returns the complete frame; caller owns the payload memory.
    pub fn readFrame(self: *Self, reader: anytype) !Frame {
        while (true) {
            var hdr_buf: [9]u8 = undefined;
            try readExact(reader, &hdr_buf);
            const hdr = Http2FrameHeader.parse(hdr_buf);

            // Enforce MAX_FRAME_SIZE (RFC 7540 §4.2).
            if (hdr.length > self.local_settings.max_frame_size) return error.FrameSizeError;

            const payload = try self.allocator.alloc(u8, hdr.length);
            errdefer self.allocator.free(payload);
            try readExact(reader, payload);

            // CONTINUATION reassembly (RFC 7540 §6.10).
            if (self.continuation_stream_id) |cont_id| {
                if (hdr.frame_type != .continuation or hdr.stream_id != cont_id) {
                    self.allocator.free(payload);
                    return error.ProtocolError;
                }
                try self.continuation_buf.appendSlice(self.allocator, payload);
                self.allocator.free(payload);

                if (hdr.flags & FLAG_END_HEADERS != 0) {
                    const assembled = try self.continuation_buf.toOwnedSlice(self.allocator);
                    const stream_id = cont_id;
                    const flags = self.continuation_flags | FLAG_END_HEADERS;
                    self.continuation_stream_id = null;
                    self.continuation_flags = 0;
                    return .{
                        .header = .{
                            .length = @intCast(assembled.len),
                            .frame_type = .headers,
                            .flags = flags,
                            .stream_id = stream_id,
                        },
                        .payload = assembled,
                    };
                }
                continue;
            }

            // Check if this HEADERS frame needs CONTINUATION reassembly.
            if (hdr.frame_type == .headers and hdr.flags & FLAG_END_HEADERS == 0) {
                self.continuation_stream_id = hdr.stream_id;
                self.continuation_flags = hdr.flags;
                self.continuation_buf.clearRetainingCapacity();
                try self.continuation_buf.appendSlice(self.allocator, payload);
                self.allocator.free(payload);
                continue;
            }

            return .{ .header = hdr, .payload = payload };
        }
    }

    /// Writes a single frame (header + payload).
    pub fn writeFrame(self: *Self, writer: anytype, frame_type: Http2FrameType, flags: u8, stream_id: u31, payload: []const u8) !void {
        _ = self;
        const hdr = Http2FrameHeader{
            .length = @intCast(payload.len),
            .frame_type = frame_type,
            .flags = flags,
            .stream_id = stream_id,
        };
        const hdr_bytes = hdr.serialize();
        try writer.writeAll(&hdr_bytes);
        if (payload.len > 0) try writer.writeAll(payload);
    }

    /// Sends HEADERS (+ CONTINUATION if needed), splitting at MAX_FRAME_SIZE.
    pub fn writeHeaders(self: *Self, writer: anytype, stream_id: u31, header_block: []const u8, end_stream: bool) !void {
        const max_size = self.peer_settings.max_frame_size;
        if (header_block.len <= max_size) {
            var flags: u8 = FLAG_END_HEADERS;
            if (end_stream) flags |= FLAG_END_STREAM;
            try self.writeFrame(writer, .headers, flags, stream_id, header_block);
        } else {
            var flags: u8 = 0;
            if (end_stream) flags |= FLAG_END_STREAM;
            try self.writeFrame(writer, .headers, flags, stream_id, header_block[0..max_size]);

            var offset: usize = max_size;
            while (offset < header_block.len) {
                const end = @min(offset + max_size, header_block.len);
                const cont_flags: u8 = if (end == header_block.len) FLAG_END_HEADERS else 0;
                try self.writeFrame(writer, .continuation, cont_flags, stream_id, header_block[offset..end]);
                offset = end;
            }
        }
    }

    /// Sends DATA frame(s), respecting peer's MAX_FRAME_SIZE.
    /// Returns error.FlowControlError if the send window is exhausted.
    pub fn writeData(self: *Self, writer: anytype, stream_id: u31, data: []const u8, end_stream: bool) !void {
        const max_size = self.peer_settings.max_frame_size;
        const stream = self.stream_manager.getStream(stream_id) orelse return error.InvalidStreamId;

        const data_i32: i32 = @intCast(data.len);
        if (stream.send_window < data_i32) return error.FlowControlError;
        if (self.stream_manager.connection_send_window < data_i32) return error.FlowControlError;

        try stream.updateSendWindow(-data_i32);
        try self.stream_manager.updateConnectionSendWindow(-data_i32);

        var offset: usize = 0;
        while (offset < data.len) {
            const end = @min(offset + max_size, data.len);
            const is_last = (end == data.len);
            const flags: u8 = if (is_last and end_stream) FLAG_END_STREAM else 0;
            try self.writeFrame(writer, .data, flags, stream_id, data[offset..end]);
            offset = end;
        }

        if (data.len == 0 and end_stream) {
            try self.writeFrame(writer, .data, FLAG_END_STREAM, stream_id, &.{});
        }

        if (end_stream) stream.sendEndStream();
    }

    // ---------------------------------------------------------------
    // Connection-level frame handlers
    // ---------------------------------------------------------------

    /// Handles a received SETTINGS frame.
    pub fn handleSettings(self: *Self, frame: *const Frame, writer: anytype) !void {
        if (frame.header.stream_id != 0) return error.ProtocolError;
        if (frame.header.flags & FLAG_ACK != 0) {
            if (frame.payload.len != 0) return error.FrameSizeError;
            return;
        }
        try self.applyPeerSettings(frame.payload);
        try self.sendSettingsAck(writer);
    }

    /// Handles a received PING frame — echoes back with ACK.
    pub fn handlePing(self: *Self, frame: *const Frame, writer: anytype) !void {
        if (frame.header.stream_id != 0) return error.ProtocolError;
        if (frame.payload.len != 8) return error.FrameSizeError;
        if (frame.header.flags & FLAG_ACK != 0) return;
        try self.writeFrame(writer, .ping, FLAG_ACK, 0, frame.payload);
    }

    /// Handles a received WINDOW_UPDATE frame.
    pub fn handleWindowUpdate(self: *Self, frame: *const Frame) !void {
        const increment = try stream_mod.parseWindowUpdatePayload(frame.payload);
        if (frame.header.stream_id == 0) {
            try self.stream_manager.updateConnectionSendWindow(@intCast(increment));
        } else {
            const s = self.stream_manager.getStream(frame.header.stream_id) orelse return;
            try s.updateSendWindow(@intCast(increment));
        }
    }

    /// Handles a received GOAWAY frame.
    pub fn handleGoaway(self: *Self, frame: *const Frame) !void {
        if (frame.payload.len < 8) return error.FrameSizeError;
        self.last_peer_stream_id = @intCast(mem.readInt(u32, frame.payload[0..4], .big) & 0x7FFFFFFF);
        self.goaway_received = true;
    }

    /// Handles a received RST_STREAM frame.
    pub fn handleRstStream(self: *Self, frame: *const Frame) !void {
        if (frame.header.stream_id == 0) return error.ProtocolError;
        const s = self.stream_manager.getStream(frame.header.stream_id) orelse return;
        s.reset();
    }

    /// Sends a GOAWAY frame advertising the last stream ID we processed.
    pub fn sendGoaway(self: *Self, writer: anytype, error_code: Http2ErrorCode) !void {
        const last_id = if (self.is_server) self.stream_manager.next_client_stream_id -| 2 else self.stream_manager.next_server_stream_id -| 2;
        const payload = try stream_mod.buildGoawayPayload(@intCast(last_id), error_code, null, self.allocator);
        defer self.allocator.free(payload);
        try self.writeFrame(writer, .goaway, 0, 0, payload);
        self.goaway_sent = true;
    }

    /// Returns true if the connection is draining (GOAWAY sent or received)
    /// and no streams are still open.
    pub fn isDrained(self: *const Self) bool {
        return (self.goaway_sent or self.goaway_received) and
            self.stream_manager.activeStreamCount() == 0;
    }

    /// Initiates graceful shutdown: sends GOAWAY with no_error, then pumps
    /// frames until all in-flight streams complete or the peer closes.
    pub fn gracefulShutdown(self: *Self, reader: anytype, writer: anytype) !void {
        if (!self.goaway_sent) {
            try self.sendGoaway(writer, .no_error);
        }
        // Drain remaining stream frames until all streams are done.
        while (self.stream_manager.activeStreamCount() > 0) {
            _ = self.processOneFrame(reader, writer) catch |err| switch (err) {
                error.ConnectionClosed => return,
                else => return err,
            };
        }
    }

    /// Sends a RST_STREAM frame.
    pub fn sendRstStream(self: *Self, writer: anytype, stream_id: u31, error_code: Http2ErrorCode) !void {
        const payload = stream_mod.buildRstStreamPayload(error_code);
        try self.writeFrame(writer, .rst_stream, 0, stream_id, &payload);
    }

    /// Sends a WINDOW_UPDATE frame for connection (stream_id=0) or a specific stream.
    pub fn sendWindowUpdate(self: *Self, writer: anytype, stream_id: u31, increment: u31) !void {
        const payload = stream_mod.buildWindowUpdatePayload(increment);
        try self.writeFrame(writer, .window_update, 0, stream_id, &payload);
    }

    // ---------------------------------------------------------------
    // Dispatching
    // ---------------------------------------------------------------

    /// Processes one frame: dispatches connection-level frames internally,
    /// returns stream-level frames (HEADERS, DATA, RST_STREAM) to the caller.
    /// Returns null for connection-level frames that were handled internally.
    pub fn dispatchFrame(self: *Self, frame: *Frame, writer: anytype) !?Frame {
        return switch (frame.header.frame_type) {
            .settings => {
                try self.handleSettings(frame, writer);
                return null;
            },
            .ping => {
                try self.handlePing(frame, writer);
                return null;
            },
            .window_update => {
                try self.handleWindowUpdate(frame);
                return null;
            },
            .goaway => {
                try self.handleGoaway(frame);
                return null;
            },
            .headers, .data, .rst_stream, .priority => frame.*,
            else => null, // Unknown frame types MUST be ignored (RFC 7540 §4.1).
        };
    }

    // ---------------------------------------------------------------
    // Pseudo-header helpers
    // ---------------------------------------------------------------

    /// Builds HTTP/2 request pseudo-headers + regular headers as HPACK entries.
    pub fn buildRequestHeaders(
        method: []const u8,
        path: []const u8,
        scheme: []const u8,
        authority: []const u8,
        extra_headers: []const hpack.HeaderEntry,
        allocator: Allocator,
    ) ![]hpack.HeaderEntry {
        const pseudo_count: usize = 4;
        const total = pseudo_count + extra_headers.len;
        const result = try allocator.alloc(hpack.HeaderEntry, total);
        result[0] = .{ .name = ":method", .value = method };
        result[1] = .{ .name = ":scheme", .value = scheme };
        result[2] = .{ .name = ":authority", .value = authority };
        result[3] = .{ .name = ":path", .value = path };
        if (extra_headers.len > 0) {
            @memcpy(result[pseudo_count..], extra_headers);
        }
        return result;
    }

    /// Builds HTTP/2 response pseudo-headers + regular headers as HPACK entries.
    pub fn buildResponseHeaders(
        status_code: u16,
        extra_headers: []const hpack.HeaderEntry,
        status_buf: *[3]u8,
        allocator: Allocator,
    ) ![]hpack.HeaderEntry {
        const total = 1 + extra_headers.len;
        const result = try allocator.alloc(hpack.HeaderEntry, total);
        _ = std.fmt.bufPrint(status_buf, "{d}", .{status_code}) catch unreachable;
        result[0] = .{ .name = ":status", .value = status_buf };
        if (extra_headers.len > 0) {
            @memcpy(result[1..], extra_headers);
        }
        return result;
    }

    /// Encodes headers via HPACK and sends as HEADERS frame(s).
    pub fn sendHeaders(self: *Self, writer: anytype, stream_id: u31, h2_headers: []const hpack.HeaderEntry, end_stream: bool) !void {
        const encoded = try hpack.encodeHeaders(&self.stream_manager.hpack_ctx, h2_headers, self.allocator);
        defer self.allocator.free(encoded);
        try self.writeHeaders(writer, stream_id, encoded, end_stream);
    }

    /// Decodes HPACK headers from a HEADERS frame payload.
    pub const DecodeResult = struct {
        headers: []hpack.DecodedHeader,
        priority: ?StreamPriority,
    };

    pub fn decodeFrameHeaders(self: *Self, payload: []const u8, flags: u8) !DecodeResult {
        const result = try stream_mod.parseHeadersFramePayload(&self.stream_manager, payload, flags, self.allocator);
        return .{ .headers = result.headers, .priority = result.priority };
    }

    // ---------------------------------------------------------------
    // Per-stream mailbox delivery and frame pumping
    // ---------------------------------------------------------------

    /// Delivers a stream-level frame to the target stream's mailbox.
    /// Copies payload data so the original frame can be freed afterward.
    pub fn deliverToMailbox(self: *Self, frame: *const Frame) !void {
        const sid = frame.header.stream_id;
        if (sid == 0) return;

        const stream = self.stream_manager.getStream(sid) orelse
            try self.stream_manager.getOrCreateStream(sid);

        switch (frame.header.frame_type) {
            .headers => {
                if (stream.headers_payload) |old| self.allocator.free(old);
                stream.headers_payload = try self.allocator.dupe(u8, frame.payload);
                stream.headers_flags = frame.header.flags;
                stream.got_headers = true;
                if (stream.data_sem) |sem| sem.post(self.io);
                if (frame.header.flags & FLAG_END_STREAM != 0) {
                    stream.completed = true;
                    stream.receiveEndStream();
                    if (stream.completion_sem) |sem| sem.post(self.io);
                }
            },
            .data => {
                try stream.data_buf.appendSlice(self.allocator, frame.payload);
                if (stream.data_sem) |sem| sem.post(self.io);
                if (frame.header.flags & FLAG_END_STREAM != 0) {
                    stream.completed = true;
                    stream.receiveEndStream();
                    if (stream.completion_sem) |sem| sem.post(self.io);
                    if (stream.data_sem) |sem| sem.post(self.io);
                }
            },
            .rst_stream => {
                stream.stream_error = error.StreamReset;
                stream.completed = true;
                stream.reset();
                if (stream.completion_sem) |sem| sem.post(self.io);
                if (stream.data_sem) |sem| sem.post(self.io);
            },
            else => {},
        }
    }

    /// Reads one frame, handles connection-level frames internally, and
    /// delivers stream-level frames to the per-stream mailbox. Sends
    /// WINDOW_UPDATE for received DATA to keep flow control open.
    /// Returns the stream ID that received data, or null.
    pub fn processOneFrame(self: *Self, reader: anytype, writer: anytype) !?u31 {
        var frame = try self.readFrame(reader);
        defer frame.deinit(self.allocator);

        const maybe = try self.dispatchFrame(&frame, writer);
        if (maybe) |sf| {
            if (sf.header.frame_type == .data and sf.payload.len > 0) {
                const inc: u31 = @intCast(sf.payload.len);
                try self.sendWindowUpdate(writer, 0, inc);
                try self.sendWindowUpdate(writer, sf.header.stream_id, inc);
            }
            try self.deliverToMailbox(&Frame{ .header = sf.header, .payload = sf.payload });
            return sf.header.stream_id;
        }
        return null;
    }

    /// Like `processOneFrame` but acquires `write_mutex` around any frame
    /// writes (SETTINGS ACK, PING echo, WINDOW_UPDATE). Use this when
    /// handler fibers may be writing concurrently on the same connection.
    pub fn processOneFrameLocked(self: *Self, reader: anytype, writer: anytype) !?u31 {
        // Read without the lock — reading blocks on I/O and must not prevent
        // handler fibers from writing responses.
        var frame = try self.readFrame(reader);
        defer frame.deinit(self.allocator);

        // Lock for writes: dispatchFrame may send SETTINGS ACK or PING echo,
        // and we may send WINDOW_UPDATE for DATA frames.
        {
            self.write_mutex.lockUncancelable(self.io);
            defer self.write_mutex.unlock(self.io);

            const maybe = try self.dispatchFrame(&frame, writer);
            if (maybe) |sf| {
                if (sf.header.frame_type == .data and sf.payload.len > 0) {
                    const inc: u31 = @intCast(sf.payload.len);
                    try self.sendWindowUpdate(writer, 0, inc);
                    try self.sendWindowUpdate(writer, sf.header.stream_id, inc);
                }
                // deliverToMailbox copies payload, safe to call under lock.
                try self.deliverToMailbox(&Frame{ .header = sf.header, .payload = sf.payload });
                return sf.header.stream_id;
            }
        }
        return null;
    }

    /// Pumps frames until the given stream has received its HEADERS.
    pub fn awaitStreamHeaders(self: *Self, reader: anytype, writer: anytype, stream_id: u31) !void {
        while (true) {
            const stream = self.stream_manager.getStream(stream_id) orelse return error.InvalidStreamId;
            if (stream.got_headers) return;
            if (stream.stream_error) |err| return err;
            _ = try self.processOneFrame(reader, writer);
        }
    }

    /// Pumps frames until the given stream is complete (END_STREAM or error).
    pub fn awaitStreamComplete(self: *Self, reader: anytype, writer: anytype, stream_id: u31) !void {
        while (true) {
            const stream = self.stream_manager.getStream(stream_id) orelse return error.InvalidStreamId;
            if (stream.completed) {
                if (stream.stream_error) |err| return err;
                return;
            }
            _ = try self.processOneFrame(reader, writer);
        }
    }

    /// Continuously pumps frames until GOAWAY or connection error.
    /// Delivers stream-level frames to per-stream mailboxes (posting
    /// completion semaphores when set). Intended for a background
    /// receive fiber on client-side multiplexed connections.
    pub fn runReceiveLoop(self: *Self, reader: anytype, writer: anytype) !void {
        while (!self.goaway_received) {
            _ = self.processOneFrameLocked(reader, writer) catch |err| switch (err) {
                error.ConnectionClosed => return,
                else => return err,
            };
        }
    }

    // ---------------------------------------------------------------
    // I/O helpers — work with any duck-typed reader/writer
    // ---------------------------------------------------------------

    /// Reads exactly `buf.len` bytes from reader.
    /// Reader must support `.recv(buf)` (Socket) or be an Io.Reader (TLS).
    fn readExact(reader: anytype, buf: []u8) !void {
        var pos: usize = 0;
        while (pos < buf.len) {
            const n = try readSome(reader, buf[pos..]);
            if (n == 0) return error.ConnectionClosed;
            pos += n;
        }
    }

    fn readSome(reader: anytype, buf: []u8) !usize {
        // Duck-typed: try .read() first, then .recv() for Socket compatibility.
        const Reader = @TypeOf(reader);
        const Child = switch (@typeInfo(Reader)) {
            .pointer => |p| p.child,
            else => Reader,
        };
        if (@hasDecl(Child, "read")) {
            return reader.read(buf);
        } else if (@hasDecl(Child, "recv")) {
            return reader.recv(buf);
        } else if (Reader == *std.Io.Reader) {
            var iov = [_][]u8{buf};
            return reader.readVec(&iov) catch |err| switch (err) {
                error.EndOfStream => @as(usize, 0),
                else => err,
            };
        } else {
            @compileError("readSome: reader must have .read() or .recv() method, got " ++ @typeName(Reader));
        }
    }
};

// ---------------------------------------------------------------
// Test utilities: in-memory reader/writer
// ---------------------------------------------------------------

/// Duck-typed writer backed by an ArrayListUnmanaged(u8).
const TestWriter = struct {
    list: *std.ArrayListUnmanaged(u8),
    allocator: Allocator,

    pub fn writeAll(self: TestWriter, data: []const u8) !void {
        try self.list.appendSlice(self.allocator, data);
    }

    pub fn print(self: TestWriter, comptime fmt: []const u8, args: anytype) !void {
        try self.list.print(self.allocator, fmt, args);
    }
};

fn testWriter(list: *std.ArrayListUnmanaged(u8), allocator: Allocator) TestWriter {
    return .{ .list = list, .allocator = allocator };
}

/// Duck-typed reader backed by a slice cursor.
const TestReader = struct {
    data: []const u8,
    pos: usize = 0,

    pub fn read(self: *TestReader, buf: []u8) !usize {
        if (self.pos >= self.data.len) return 0;
        const available = self.data.len - self.pos;
        const n = @min(available, buf.len);
        @memcpy(buf[0..n], self.data[self.pos .. self.pos + n]);
        self.pos += n;
        return n;
    }
};

// ---------------------------------------------------------------
// Tests
// ---------------------------------------------------------------

test "connection preface round-trip" {
    const allocator = std.testing.allocator;

    var wire = std.ArrayListUnmanaged(u8).empty;
    defer wire.deinit(allocator);

    var client = H2Connection.initClient(allocator, std.testing.io);
    defer client.deinit();

    // Client writes preface + SETTINGS.
    const writer = testWriter(&wire, allocator);
    try client.sendClientPreface(writer);

    // Server reads and validates preface.
    var server = H2Connection.initServer(allocator, std.testing.io);
    defer server.deinit();

    var reader = TestReader{ .data = wire.items };
    try server.readClientPreface(&reader);

    // Server reads the SETTINGS frame.
    var frame = try server.readFrame(&reader);
    defer frame.deinit(allocator);

    try std.testing.expectEqual(Http2FrameType.settings, frame.header.frame_type);
    try std.testing.expectEqual(@as(u31, 0), frame.header.stream_id);
}

test "SETTINGS exchange" {
    const allocator = std.testing.allocator;

    var wire = std.ArrayListUnmanaged(u8).empty;
    defer wire.deinit(allocator);
    const writer = testWriter(&wire, allocator);

    var conn = H2Connection.initClient(allocator, std.testing.io);
    defer conn.deinit();
    conn.local_settings.max_concurrent_streams = 42;

    try conn.sendSettings(writer);

    var reader = TestReader{ .data = wire.items };
    var frame = try conn.readFrame(&reader);
    defer frame.deinit(allocator);

    try std.testing.expectEqual(Http2FrameType.settings, frame.header.frame_type);
    try std.testing.expect(frame.header.flags & H2Connection.FLAG_ACK == 0);

    // Apply settings on peer side.
    var peer = H2Connection.initServer(allocator, std.testing.io);
    defer peer.deinit();
    try peer.applyPeerSettings(frame.payload);
    try std.testing.expectEqual(@as(u32, 42), peer.peer_settings.max_concurrent_streams);
}

test "SETTINGS ACK" {
    const allocator = std.testing.allocator;

    var wire = std.ArrayListUnmanaged(u8).empty;
    defer wire.deinit(allocator);
    const writer = testWriter(&wire, allocator);

    var conn = H2Connection.initClient(allocator, std.testing.io);
    defer conn.deinit();
    try conn.sendSettingsAck(writer);

    var reader = TestReader{ .data = wire.items };
    var frame = try conn.readFrame(&reader);
    defer frame.deinit(allocator);

    try std.testing.expectEqual(Http2FrameType.settings, frame.header.frame_type);
    try std.testing.expect(frame.header.flags & H2Connection.FLAG_ACK != 0);
    try std.testing.expectEqual(@as(u24, 0), frame.header.length);
}

test "PING echo" {
    const allocator = std.testing.allocator;

    var wire = std.ArrayListUnmanaged(u8).empty;
    defer wire.deinit(allocator);
    const writer = testWriter(&wire, allocator);

    var conn = H2Connection.initServer(allocator, std.testing.io);
    defer conn.deinit();

    const ping_data = [8]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
    try conn.writeFrame(writer, .ping, 0, 0, &ping_data);

    // Read the PING frame.
    var reader = TestReader{ .data = wire.items };
    var frame = try conn.readFrame(&reader);

    // Handle it (should echo back).
    var reply = std.ArrayListUnmanaged(u8).empty;
    defer reply.deinit(allocator);
    const reply_writer = testWriter(&reply, allocator);

    try conn.handlePing(&frame, reply_writer);
    frame.deinit(allocator);

    // Read the PING ACK reply.
    var reply_reader = TestReader{ .data = reply.items };
    var ack = try conn.readFrame(&reply_reader);
    defer ack.deinit(allocator);

    try std.testing.expectEqual(Http2FrameType.ping, ack.header.frame_type);
    try std.testing.expect(ack.header.flags & H2Connection.FLAG_ACK != 0);
    try std.testing.expectEqualSlices(u8, &ping_data, ack.payload);
}

test "GOAWAY handling" {
    const allocator = std.testing.allocator;

    var wire = std.ArrayListUnmanaged(u8).empty;
    defer wire.deinit(allocator);
    const writer = testWriter(&wire, allocator);

    var conn = H2Connection.initClient(allocator, std.testing.io);
    defer conn.deinit();

    // Build a GOAWAY frame (last_stream_id=7, no_error).
    var goaway_payload: [8]u8 = undefined;
    mem.writeInt(u32, goaway_payload[0..4], 7, .big);
    mem.writeInt(u32, goaway_payload[4..8], @intFromEnum(Http2ErrorCode.no_error), .big);
    try conn.writeFrame(writer, .goaway, 0, 0, &goaway_payload);

    var reader = TestReader{ .data = wire.items };
    var frame = try conn.readFrame(&reader);
    defer frame.deinit(allocator);

    try conn.handleGoaway(&frame);
    try std.testing.expect(conn.goaway_received);
    try std.testing.expectEqual(@as(u31, 7), conn.last_peer_stream_id);
}

test "WINDOW_UPDATE handling" {
    const allocator = std.testing.allocator;

    var wire = std.ArrayListUnmanaged(u8).empty;
    defer wire.deinit(allocator);
    const writer = testWriter(&wire, allocator);

    var conn = H2Connection.initClient(allocator, std.testing.io);
    defer conn.deinit();

    const initial_window = conn.stream_manager.connection_send_window;

    const wu_payload = stream_mod.buildWindowUpdatePayload(1000);
    try conn.writeFrame(writer, .window_update, 0, 0, &wu_payload);

    var reader = TestReader{ .data = wire.items };
    var frame = try conn.readFrame(&reader);
    defer frame.deinit(allocator);

    try conn.handleWindowUpdate(&frame);
    try std.testing.expectEqual(initial_window + 1000, conn.stream_manager.connection_send_window);
}

test "HEADERS with CONTINUATION reassembly" {
    const allocator = std.testing.allocator;

    var wire = std.ArrayListUnmanaged(u8).empty;
    defer wire.deinit(allocator);
    const writer = testWriter(&wire, allocator);

    var conn = H2Connection.initClient(allocator, std.testing.io);
    defer conn.deinit();

    // HEADERS frame without END_HEADERS + CONTINUATION with END_HEADERS.
    const part1 = "hello";
    const part2 = " world";
    try conn.writeFrame(writer, .headers, H2Connection.FLAG_END_STREAM, 1, part1);
    try conn.writeFrame(writer, .continuation, H2Connection.FLAG_END_HEADERS, 1, part2);

    var reader = TestReader{ .data = wire.items };
    var frame = try conn.readFrame(&reader);
    defer frame.deinit(allocator);

    try std.testing.expectEqual(Http2FrameType.headers, frame.header.frame_type);
    try std.testing.expect(frame.header.flags & H2Connection.FLAG_END_HEADERS != 0);
    try std.testing.expect(frame.header.flags & H2Connection.FLAG_END_STREAM != 0);
    try std.testing.expectEqualSlices(u8, "hello world", frame.payload);
}

test "single HEADERS frame (no CONTINUATION)" {
    const allocator = std.testing.allocator;

    var wire = std.ArrayListUnmanaged(u8).empty;
    defer wire.deinit(allocator);
    const writer = testWriter(&wire, allocator);

    var conn = H2Connection.initClient(allocator, std.testing.io);
    defer conn.deinit();

    try conn.writeFrame(writer, .headers, H2Connection.FLAG_END_HEADERS | H2Connection.FLAG_END_STREAM, 1, "complete");

    var reader = TestReader{ .data = wire.items };
    var frame = try conn.readFrame(&reader);
    defer frame.deinit(allocator);

    try std.testing.expectEqual(Http2FrameType.headers, frame.header.frame_type);
    try std.testing.expectEqualSlices(u8, "complete", frame.payload);
}

test "writeHeaders splits at MAX_FRAME_SIZE" {
    const allocator = std.testing.allocator;

    var wire = std.ArrayListUnmanaged(u8).empty;
    defer wire.deinit(allocator);
    const writer = testWriter(&wire, allocator);

    var conn = H2Connection.initClient(allocator, std.testing.io);
    defer conn.deinit();
    conn.peer_settings.max_frame_size = 10;

    const block = "ABCDEFGHIJKLMNOPQRSTUVWXY"; // 25 bytes → 3 frames
    try conn.writeHeaders(writer, 1, block, true);

    // Read back with CONTINUATION reassembly.
    var conn2 = H2Connection.initClient(allocator, std.testing.io);
    defer conn2.deinit();
    conn2.local_settings.max_frame_size = 16384; // Allow reading large reassembled payload.

    var reader = TestReader{ .data = wire.items };
    var reassembled = try conn2.readFrame(&reader);
    defer reassembled.deinit(allocator);

    try std.testing.expectEqual(Http2FrameType.headers, reassembled.header.frame_type);
    try std.testing.expect(reassembled.header.flags & H2Connection.FLAG_END_HEADERS != 0);
    try std.testing.expectEqualSlices(u8, block, reassembled.payload);
}

test "dispatchFrame routes correctly" {
    const allocator = std.testing.allocator;

    var wire = std.ArrayListUnmanaged(u8).empty;
    defer wire.deinit(allocator);
    const writer = testWriter(&wire, allocator);

    var conn = H2Connection.initServer(allocator, std.testing.io);
    defer conn.deinit();

    try conn.sendSettings(writer);

    var reader = TestReader{ .data = wire.items };
    var frame = try conn.readFrame(&reader);

    var reply = std.ArrayListUnmanaged(u8).empty;
    defer reply.deinit(allocator);
    const reply_writer = testWriter(&reply, allocator);

    const result = try conn.dispatchFrame(&frame, reply_writer);
    frame.deinit(allocator);
    try std.testing.expect(result == null);
}

test "buildRequestHeaders" {
    const allocator = std.testing.allocator;
    const extra = [_]hpack.HeaderEntry{
        .{ .name = "content-type", .value = "application/json" },
    };
    const h = try H2Connection.buildRequestHeaders("GET", "/index.html", "https", "example.com", &extra, allocator);
    defer allocator.free(h);

    try std.testing.expectEqual(@as(usize, 5), h.len);
    try std.testing.expectEqualStrings(":method", h[0].name);
    try std.testing.expectEqualStrings("GET", h[0].value);
    try std.testing.expectEqualStrings(":scheme", h[1].name);
    try std.testing.expectEqualStrings(":path", h[3].name);
    try std.testing.expectEqualStrings("/index.html", h[3].value);
    try std.testing.expectEqualStrings("content-type", h[4].name);
}

test "buildResponseHeaders" {
    const allocator = std.testing.allocator;
    var status_buf: [3]u8 = undefined;
    const extra = [_]hpack.HeaderEntry{
        .{ .name = "content-type", .value = "text/html" },
    };
    const h = try H2Connection.buildResponseHeaders(200, &extra, &status_buf, allocator);
    defer allocator.free(h);

    try std.testing.expectEqual(@as(usize, 2), h.len);
    try std.testing.expectEqualStrings(":status", h[0].name);
    try std.testing.expectEqualStrings("200", h[0].value);
}

test "HPACK encode + decode round-trip via sendHeaders/decodeFrameHeaders" {
    const allocator = std.testing.allocator;

    var wire = std.ArrayListUnmanaged(u8).empty;
    defer wire.deinit(allocator);
    const writer = testWriter(&wire, allocator);

    var client = H2Connection.initClient(allocator, std.testing.io);
    defer client.deinit();

    const h2_headers = [_]hpack.HeaderEntry{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
    };
    try client.sendHeaders(writer, 1, &h2_headers, true);

    // Decode on server side.
    var server = H2Connection.initServer(allocator, std.testing.io);
    defer server.deinit();

    var reader = TestReader{ .data = wire.items };
    var frame = try server.readFrame(&reader);
    defer frame.deinit(allocator);

    try std.testing.expectEqual(Http2FrameType.headers, frame.header.frame_type);

    const decoded = try server.decodeFrameHeaders(frame.payload, frame.header.flags);
    defer {
        for (decoded.headers) |h| {
            allocator.free(h.name);
            allocator.free(h.value);
        }
        allocator.free(decoded.headers);
    }

    try std.testing.expectEqual(@as(usize, 4), decoded.headers.len);
    try std.testing.expectEqualStrings(":method", decoded.headers[0].name);
    try std.testing.expectEqualStrings("GET", decoded.headers[0].value);
    try std.testing.expectEqualStrings(":path", decoded.headers[1].name);
    try std.testing.expectEqualStrings("/", decoded.headers[1].value);
    try std.testing.expectEqualStrings(":authority", decoded.headers[3].name);
    try std.testing.expectEqualStrings("example.com", decoded.headers[3].value);
}

test "full HTTP/2 request-response round-trip" {
    const allocator = std.testing.allocator;

    // Simulate client → server → client using in-memory buffers.

    // --- Client sends preface + SETTINGS + request ---
    var c2s = std.ArrayListUnmanaged(u8).empty; // client-to-server wire
    defer c2s.deinit(allocator);
    const c2s_w = testWriter(&c2s, allocator);

    var client = H2Connection.initClient(allocator, std.testing.io);
    defer client.deinit();

    try client.sendClientPreface(c2s_w);

    // Create stream and send request HEADERS (GET /).
    _ = try client.stream_manager.createStream();
    const req_headers = [_]hpack.HeaderEntry{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
    };
    try client.sendHeaders(c2s_w, 1, &req_headers, true); // END_STREAM (no body)

    // --- Server reads preface + SETTINGS + request ---
    var server = H2Connection.initServer(allocator, std.testing.io);
    defer server.deinit();

    var s_reader = TestReader{ .data = c2s.items };
    try server.readClientPreface(&s_reader);

    // Read client's SETTINGS.
    var s2c = std.ArrayListUnmanaged(u8).empty; // server-to-client wire
    defer s2c.deinit(allocator);
    const s2c_w = testWriter(&s2c, allocator);

    var settings_frame = try server.readFrame(&s_reader);
    try server.handleSettings(&settings_frame, s2c_w); // sends ACK
    settings_frame.deinit(allocator);

    // Send server SETTINGS.
    try server.sendSettings(s2c_w);

    // Read the request HEADERS frame.
    var req_frame = try server.readFrame(&s_reader);
    defer req_frame.deinit(allocator);

    try std.testing.expectEqual(Http2FrameType.headers, req_frame.header.frame_type);
    try std.testing.expect(req_frame.header.flags & H2Connection.FLAG_END_STREAM != 0);

    const decoded = try server.decodeFrameHeaders(req_frame.payload, req_frame.header.flags);
    defer {
        for (decoded.headers) |h| {
            allocator.free(h.name);
            allocator.free(h.value);
        }
        allocator.free(decoded.headers);
    }

    // Verify server got the right request.
    try std.testing.expectEqual(@as(usize, 4), decoded.headers.len);
    try std.testing.expectEqualStrings("GET", decoded.headers[0].value);
    try std.testing.expectEqualStrings("/", decoded.headers[1].value);

    // --- Server sends response ---
    var status_buf: [3]u8 = undefined;
    const resp_extra = [_]hpack.HeaderEntry{
        .{ .name = "content-type", .value = "text/plain" },
    };
    const resp_headers = try H2Connection.buildResponseHeaders(200, &resp_extra, &status_buf, allocator);
    defer allocator.free(resp_headers);

    // Server accepts client-initiated stream 1.
    _ = try server.stream_manager.getOrCreateStream(1);
    const stream_id: u31 = 1;

    try server.sendHeaders(s2c_w, stream_id, resp_headers, false);
    const body = "Hello, HTTP/2!";
    try server.writeData(s2c_w, stream_id, body, true);

    // --- Client reads response ---
    var c_reader = TestReader{ .data = s2c.items };

    // Read and dispatch connection-level frames until we get the response HEADERS.
    var got_status: ?[]const u8 = null;
    var got_body = std.ArrayListUnmanaged(u8).empty;
    defer got_body.deinit(allocator);
    var resp_decoded: ?[]hpack.DecodedHeader = null;
    defer if (resp_decoded) |hdrs| {
        for (hdrs) |*h| {
            allocator.free(h.name);
            allocator.free(h.value);
        }
        allocator.free(hdrs);
    };

    var end_stream = false;
    while (!end_stream) {
        var frame = try client.readFrame(&c_reader);
        defer frame.deinit(allocator);

        const maybe = try client.dispatchFrame(&frame, c2s_w);
        if (maybe == null) continue;

        const sf = maybe.?;
        switch (sf.header.frame_type) {
            .headers => {
                const dec = try client.decodeFrameHeaders(sf.payload, sf.header.flags);
                resp_decoded = dec.headers;
                for (dec.headers) |h| {
                    if (mem.eql(u8, h.name, ":status")) got_status = h.value;
                }
                if (sf.header.flags & H2Connection.FLAG_END_STREAM != 0) end_stream = true;
            },
            .data => {
                if (sf.payload.len > 0) try got_body.appendSlice(allocator, sf.payload);
                if (sf.header.flags & H2Connection.FLAG_END_STREAM != 0) end_stream = true;
            },
            else => {},
        }
    }

    // Verify the response.
    try std.testing.expectEqualStrings("200", got_status.?);
    try std.testing.expectEqualStrings("Hello, HTTP/2!", got_body.items);
}

test "mailbox-based request-response round-trip" {
    const allocator = std.testing.allocator;

    // --- Client sends preface + SETTINGS + request ---
    var c2s = std.ArrayListUnmanaged(u8).empty;
    defer c2s.deinit(allocator);
    const c2s_w = testWriter(&c2s, allocator);

    var client = H2Connection.initClient(allocator, std.testing.io);
    defer client.deinit();

    try client.sendClientPreface(c2s_w);

    _ = try client.stream_manager.createStream();
    const req_headers = [_]hpack.HeaderEntry{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = "/api/data" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
    };
    try client.sendHeaders(c2s_w, 1, &req_headers, false);
    try client.writeData(c2s_w, 1, "request body", true);

    // --- Server reads via mailbox pattern ---
    var server = H2Connection.initServer(allocator, std.testing.io);
    defer server.deinit();

    var s_reader = TestReader{ .data = c2s.items };
    try server.readClientPreface(&s_reader);

    var s2c = std.ArrayListUnmanaged(u8).empty;
    defer s2c.deinit(allocator);
    const s2c_w = testWriter(&s2c, allocator);

    // Read client SETTINGS.
    var settings_frame = try server.readFrame(&s_reader);
    try server.handleSettings(&settings_frame, s2c_w);
    settings_frame.deinit(allocator);

    try server.sendSettings(s2c_w);

    // Pump frames until stream 1 is complete.
    while (true) {
        _ = try server.processOneFrame(&s_reader, s2c_w);
        if (server.stream_manager.getStream(1)) |s| {
            if (s.completed) break;
        }
    }

    // Verify mailbox contents.
    const s1 = server.stream_manager.getStream(1).?;
    try std.testing.expect(s1.got_headers);
    try std.testing.expect(s1.completed);
    try std.testing.expect(s1.headers_payload != null);
    try std.testing.expectEqualStrings("request body", s1.data_buf.items);

    // Decode headers from mailbox.
    const dec = try server.decodeFrameHeaders(s1.headers_payload.?, s1.headers_flags);
    defer {
        for (dec.headers) |h| {
            allocator.free(h.name);
            allocator.free(h.value);
        }
        allocator.free(dec.headers);
    }
    try std.testing.expectEqualStrings(":method", dec.headers[0].name);
    try std.testing.expectEqualStrings("POST", dec.headers[0].value);
    try std.testing.expectEqualStrings("/api/data", dec.headers[1].value);

    // --- Server sends response, client reads via awaitStreamComplete ---
    var status_buf: [3]u8 = undefined;
    const resp_headers = try H2Connection.buildResponseHeaders(201, &.{}, &status_buf, allocator);
    defer allocator.free(resp_headers);

    _ = try server.stream_manager.getOrCreateStream(1);
    try server.sendHeaders(s2c_w, 1, resp_headers, false);
    try server.writeData(s2c_w, 1, "response body", true);

    // Client uses awaitStreamComplete.
    var c_reader = TestReader{ .data = s2c.items };
    try client.awaitStreamComplete(&c_reader, c2s_w, 1);

    const cs1 = client.stream_manager.getStream(1).?;
    try std.testing.expect(cs1.completed);
    try std.testing.expect(cs1.got_headers);
    try std.testing.expectEqualStrings("response body", cs1.data_buf.items);

    // Decode response headers from mailbox.
    const rdec = try client.decodeFrameHeaders(cs1.headers_payload.?, cs1.headers_flags);
    defer {
        for (rdec.headers) |h| {
            allocator.free(h.name);
            allocator.free(h.value);
        }
        allocator.free(rdec.headers);
    }
    try std.testing.expectEqualStrings(":status", rdec.headers[0].name);
    try std.testing.expectEqualStrings("201", rdec.headers[0].value);
}

test "deliverToMailbox incremental DATA without END_STREAM" {
    const allocator = std.testing.allocator;

    var server = H2Connection.initServer(allocator, std.testing.io);
    defer server.deinit();

    const stream = try server.stream_manager.getOrCreateStream(1);

    // Deliver a DATA frame without END_STREAM.
    var payload1 = try allocator.dupe(u8, "chunk1");
    defer allocator.free(payload1);
    var frame1 = Frame{
        .header = .{
            .length = @intCast(payload1.len),
            .frame_type = .data,
            .flags = 0, // no END_STREAM
            .stream_id = 1,
        },
        .payload = payload1,
    };
    try server.deliverToMailbox(&frame1);

    // Stream should have data but NOT be completed.
    try std.testing.expectEqualStrings("chunk1", stream.data_buf.items);
    try std.testing.expect(!stream.completed);
    try std.testing.expectEqual(@as(usize, 0), stream.read_offset);

    // Deliver a second DATA frame without END_STREAM.
    var payload2 = try allocator.dupe(u8, "chunk2");
    defer allocator.free(payload2);
    var frame2 = Frame{
        .header = .{
            .length = @intCast(payload2.len),
            .frame_type = .data,
            .flags = 0,
            .stream_id = 1,
        },
        .payload = payload2,
    };
    try server.deliverToMailbox(&frame2);

    try std.testing.expectEqualStrings("chunk1chunk2", stream.data_buf.items);
    try std.testing.expect(!stream.completed);

    // Deliver a final DATA frame WITH END_STREAM.
    var payload3 = try allocator.dupe(u8, "chunk3");
    defer allocator.free(payload3);
    var frame3 = Frame{
        .header = .{
            .length = @intCast(payload3.len),
            .frame_type = .data,
            .flags = H2Connection.FLAG_END_STREAM,
            .stream_id = 1,
        },
        .payload = payload3,
    };
    try server.deliverToMailbox(&frame3);

    try std.testing.expectEqualStrings("chunk1chunk2chunk3", stream.data_buf.items);
    try std.testing.expect(stream.completed);
}

test "h2 streaming: server sends incremental DATA, client reads chunks" {
    const allocator = std.testing.allocator;

    // Server: send HEADERS (no END_STREAM) + 3 DATA chunks + END_STREAM.
    var s2c = std.ArrayListUnmanaged(u8).empty;
    defer s2c.deinit(allocator);
    const s2c_w = testWriter(&s2c, allocator);

    var server = H2Connection.initServer(allocator, std.testing.io);
    defer server.deinit();

    const stream = try server.stream_manager.getOrCreateStream(1);
    _ = stream;

    var status_buf: [3]u8 = undefined;
    const resp_headers = try H2Connection.buildResponseHeaders(200, &.{}, &status_buf, allocator);
    defer allocator.free(resp_headers);

    // Send HEADERS without END_STREAM.
    try server.sendHeaders(s2c_w, 1, resp_headers, false);

    // Send 3 DATA chunks without END_STREAM.
    try server.writeData(s2c_w, 1, "chunk1", false);
    try server.writeData(s2c_w, 1, "chunk2", false);
    try server.writeData(s2c_w, 1, "chunk3", true); // END_STREAM

    // Client: read the frames and verify incremental delivery.
    var client = H2Connection.initClient(allocator, std.testing.io);
    defer client.deinit();

    // Client must have stream 1 registered (normally created when sending the request).
    _ = try client.stream_manager.createStream();

    var reader = TestReader{ .data = s2c.items };

    // Process HEADERS frame.
    const sid1 = try client.processOneFrame(&reader, s2c_w);
    try std.testing.expectEqual(@as(?u31, 1), sid1);
    const cs = client.stream_manager.getStream(1).?;
    try std.testing.expect(cs.got_headers);
    try std.testing.expect(!cs.completed);

    // Process first DATA frame — should have "chunk1" but not be completed.
    _ = try client.processOneFrame(&reader, s2c_w);
    try std.testing.expectEqualStrings("chunk1", cs.data_buf.items);
    try std.testing.expect(!cs.completed);

    // Process second DATA frame — accumulated data.
    _ = try client.processOneFrame(&reader, s2c_w);
    try std.testing.expectEqualStrings("chunk1chunk2", cs.data_buf.items);
    try std.testing.expect(!cs.completed);

    // Process third DATA frame with END_STREAM.
    _ = try client.processOneFrame(&reader, s2c_w);
    try std.testing.expectEqualStrings("chunk1chunk2chunk3", cs.data_buf.items);
    try std.testing.expect(cs.completed);

    // Verify read_offset is usable for incremental consumption.
    try std.testing.expectEqual(@as(usize, 0), cs.read_offset);
    cs.read_offset = 6; // consumed "chunk1"
    const remaining = cs.data_buf.items[cs.read_offset..];
    try std.testing.expectEqualStrings("chunk2chunk3", remaining);
}

test "h2 streaming over TCP: incremental DATA frames" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const socket_mod = @import("../net/socket.zig");
    const Socket = socket_mod.Socket;
    const Address = socket_mod.Address;
    const TcpListener = socket_mod.TcpListener;

    // 1. Bind listener.
    const listen_addr = Address{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } };
    var listener = try TcpListener.init(listen_addr, io);
    defer listener.deinit();
    const bound_addr = listener.getLocalAddress();

    // 2. Client: connect, send h2 preface + GET request.
    var client_sock = try Socket.connect(bound_addr, io);
    defer client_sock.close();

    var client_h2 = H2Connection.initClient(allocator, io);
    defer client_h2.deinit();

    try client_h2.sendClientPreface(&client_sock);
    const req_headers = try H2Connection.buildRequestHeaders("GET", "/stream", "http", "localhost", &.{}, allocator);
    defer allocator.free(req_headers);
    const stream = try client_h2.stream_manager.createStream();
    const stream_id = stream.id;
    try client_h2.sendHeaders(&client_sock, stream_id, req_headers, true);

    // 3. Server: accept, handshake, read request.
    const accept_result = try listener.accept();
    var server_sock = accept_result.socket;
    defer server_sock.close();

    var server_h2 = H2Connection.initServer(allocator, io);
    defer server_h2.deinit();

    var preface_buf: [24]u8 = undefined;
    H2Connection.readExact(&server_sock, &preface_buf) catch return;
    if (!mem.eql(u8, &preface_buf, http.HTTP2_PREFACE)) return error.ProtocolError;

    var settings_frame = try server_h2.readFrame(&server_sock);
    defer settings_frame.deinit(allocator);
    try server_h2.handleSettings(&settings_frame, &server_sock);
    try server_h2.sendSettings(&server_sock);

    // Pump until request stream completes.
    var completed_sid: ?u31 = null;
    while (completed_sid == null) {
        const maybe_sid = try server_h2.processOneFrame(&server_sock, &server_sock);
        if (maybe_sid) |sid| {
            const s = server_h2.stream_manager.getStream(sid) orelse continue;
            if (s.completed) completed_sid = sid;
        }
    }

    // 4. Server: send HEADERS (no END_STREAM) + 3 DATA chunks + END_STREAM.
    var status_buf: [3]u8 = undefined;
    const resp_headers = try H2Connection.buildResponseHeaders(200, &.{}, &status_buf, allocator);
    defer allocator.free(resp_headers);
    try server_h2.sendHeaders(&server_sock, completed_sid.?, resp_headers, false);
    try server_h2.writeData(&server_sock, completed_sid.?, "aaa", false);
    try server_h2.writeData(&server_sock, completed_sid.?, "bbb", false);
    try server_h2.writeData(&server_sock, completed_sid.?, "ccc", true);

    // 5. Client: read frames one at a time, verify incremental data.
    const cs = client_h2.stream_manager.getStream(stream_id).?;

    // Pump until we get HEADERS + all DATA.
    while (!cs.completed) {
        _ = try client_h2.processOneFrame(&client_sock, &client_sock);
    }

    try std.testing.expect(cs.got_headers);
    try std.testing.expect(cs.completed);
    try std.testing.expectEqualStrings("aaabbbccc", cs.data_buf.items);

    // Verify read_offset incremental consumption.
    var out: [3]u8 = undefined;
    @memcpy(&out, cs.data_buf.items[cs.read_offset..][0..3]);
    try std.testing.expectEqualStrings("aaa", &out);
    cs.read_offset += 3;
    @memcpy(&out, cs.data_buf.items[cs.read_offset..][0..3]);
    try std.testing.expectEqualStrings("bbb", &out);
    cs.read_offset += 3;
    @memcpy(&out, cs.data_buf.items[cs.read_offset..][0..3]);
    try std.testing.expectEqualStrings("ccc", &out);
    cs.read_offset += 3;
    try std.testing.expectEqual(cs.data_buf.items.len, cs.read_offset);
}

test "h2 round-trip over TCP loopback" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const socket_mod = @import("../net/socket.zig");
    const Socket = socket_mod.Socket;
    const Address = socket_mod.Address;
    const TcpListener = socket_mod.TcpListener;

    // 1. Bind listener on ephemeral port.
    const listen_addr = Address{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } };
    var listener = try TcpListener.init(listen_addr, io);
    defer listener.deinit();
    const bound_addr = listener.getLocalAddress();

    // 2. Client: connect and burst-write the h2 handshake + request.
    var client_sock = try Socket.connect(bound_addr, io);
    defer client_sock.close();

    var client_h2 = H2Connection.initClient(allocator, io);
    defer client_h2.deinit();

    // Send client preface (magic + SETTINGS).
    try client_h2.sendClientPreface(&client_sock);

    // Build and send a GET / request.
    const req_headers = try H2Connection.buildRequestHeaders(
        "GET", "/", "http", "localhost", &.{}, allocator,
    );
    defer allocator.free(req_headers);
    const stream = try client_h2.stream_manager.createStream();
    const stream_id = stream.id;
    try client_h2.sendHeaders(&client_sock, stream_id, req_headers, true); // END_STREAM

    // 3. Server: accept and process the h2 handshake + request.
    const accept_result = try listener.accept();
    var server_sock = accept_result.socket;
    defer server_sock.close();

    var server_h2 = H2Connection.initServer(allocator, io);
    defer server_h2.deinit();

    // Read client preface (24-byte magic).
    var preface_buf: [24]u8 = undefined;
    H2Connection.readExact(&server_sock, &preface_buf) catch return;
    if (!mem.eql(u8, &preface_buf, http.HTTP2_PREFACE)) return error.ProtocolError;

    // Read client's SETTINGS frame and ACK it.
    var settings_frame = try server_h2.readFrame(&server_sock);
    defer settings_frame.deinit(allocator);
    if (settings_frame.header.frame_type != .settings) return error.ProtocolError;
    try server_h2.handleSettings(&settings_frame, &server_sock);

    // Send server SETTINGS.
    try server_h2.sendSettings(&server_sock);

    // Pump frames until a stream completes (reads client's HEADERS + SETTINGS ACK).
    var completed_sid: ?u31 = null;
    while (completed_sid == null) {
        const maybe_sid = try server_h2.processOneFrame(&server_sock, &server_sock);
        if (maybe_sid) |sid| {
            const s = server_h2.stream_manager.getStream(sid) orelse continue;
            if (s.completed) completed_sid = sid;
        }
    }

    // Verify the server received the request headers.
    const srv_stream = server_h2.stream_manager.getStream(completed_sid.?).?;
    try std.testing.expect(srv_stream.got_headers);
    try std.testing.expect(srv_stream.completed);

    // 4. Server sends a 200 response with body "hello".
    var status_buf: [3]u8 = undefined;
    const resp_headers = try H2Connection.buildResponseHeaders(200, &.{}, &status_buf, allocator);
    defer allocator.free(resp_headers);
    try server_h2.sendHeaders(&server_sock, completed_sid.?, resp_headers, false);
    try server_h2.writeData(&server_sock, completed_sid.?, "hello", true);

    // 5. Client reads the response (pump frames for server SETTINGS + response).
    try client_h2.awaitStreamComplete(&client_sock, &client_sock, stream_id);

    const resp_stream = client_h2.stream_manager.getStream(stream_id).?;
    try std.testing.expect(resp_stream.completed);
    try std.testing.expectEqualStrings("hello", resp_stream.data_buf.items);

    // Decode response headers to verify status.
    const resp_dec = try client_h2.decodeFrameHeaders(
        resp_stream.headers_payload.?, resp_stream.headers_flags,
    );
    defer {
        for (resp_dec.headers) |h| {
            allocator.free(h.name);
            allocator.free(h.value);
        }
        allocator.free(resp_dec.headers);
    }
    try std.testing.expectEqualStrings(":status", resp_dec.headers[0].name);
    try std.testing.expectEqualStrings("200", resp_dec.headers[0].value);
}
