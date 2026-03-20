# UDP Local

Run the local UDP transport helper flow.

## Demo Program

```zig
const std = @import("std");
const httpx = @import("httpx");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var transport = try httpx.QuicTransport.init(allocator);
    defer transport.deinit();

    try transport.bind("127.0.0.1", 4444);
    std.debug.print("udp local transport bound on 127.0.0.1:4444\n", .{});
}
```

## Run

```bash
zig build run-udp_local
```

## What to Verify

- UDP bind succeeds on local interface.
- Transport deinitializes cleanly.
