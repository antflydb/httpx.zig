# Simple Server

Start a minimal server and return JSON from a single route.

## Demo Program

```zig
const std = @import("std");
const httpx = @import("httpx");

fn health(ctx: *httpx.Context) anyerror!httpx.Response {
    return ctx.json(.{ .ok = true, .service = "demo" });
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var server = httpx.Server.initWithConfig(allocator, .{
        .host = "127.0.0.1",
        .port = 8080,
        .max_connections = 1000,
        .keep_alive = true,
    });
    defer server.deinit();

    try server.get("/health", health);
    try server.listen();
}
```

## Run

```bash
zig build run-simple_server
```

## What to Verify

- `GET /health` returns JSON response.
- Server starts without route registration errors.
- Browser request to `http://127.0.0.1:8080/health` returns immediately.
