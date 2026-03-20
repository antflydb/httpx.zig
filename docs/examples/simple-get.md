# Simple Get

Perform a minimal HTTP GET request with `httpx.Client`.

## Demo Program

```zig
const std = @import("std");
const httpx = @import("httpx");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var client = httpx.Client.init(allocator);
    defer client.deinit();

    var res = try client.get("https://httpbin.org/get", .{});
    defer res.deinit();

    std.debug.print("status={d}\n", .{res.status.code});
    std.debug.print("body={s}\n", .{res.text() orelse ""});
}
```

## Run

```bash
zig build run-simple_get
```

## What to Verify

- Successful HTTP status code.
- Non-empty response body text.
