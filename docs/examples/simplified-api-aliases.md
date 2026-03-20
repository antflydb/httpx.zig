# Simplified API Aliases

Use concise top-level aliases for common client operations.

## Demo Program

```zig
const std = @import("std");
const httpx = @import("httpx");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var a = try httpx.fetch(allocator, "https://httpbin.org/get");
    defer a.deinit();

    var b = try httpx.send(allocator, .GET, "https://httpbin.org/headers", .{});
    defer b.deinit();

    var c = try httpx.post(allocator, "https://httpbin.org/post", .{ .json = "{\"ok\":true}" });
    defer c.deinit();

    std.debug.print("statuses: {d}, {d}, {d}\n", .{ a.status.code, b.status.code, c.status.code });
}
```

## Run

```bash
zig build run-simplified_api_aliases
```

## What to Verify

- Alias helpers behave the same as direct client methods.
- Request/response lifecycle remains correct with deinit calls.
