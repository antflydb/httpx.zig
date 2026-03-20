# Static Files

Serve files with automatic MIME type resolution.

## Demo Program

```zig
const std = @import("std");
const httpx = @import("httpx");

fn home(ctx: *httpx.Context) anyerror!httpx.Response {
    return ctx.file("examples/multi_page_site/index.html");
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var server = httpx.Server.init(allocator);
    defer server.deinit();

    try server.get("/", home);
    try server.listen();
}
```

## Run

```bash
zig build run-static_files
```

## What to Verify

- HTML file is served from disk.
- `Content-Type` matches file extension.
