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

    var server = httpx.Server.init(allocator);
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
