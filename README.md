# ztun - Cross-Platform TUN Device Library

A pure Zig library for creating/managing TUN devices with transparent proxy forwarding capabilities on Linux, macOS, and Windows.

## Features

- **TUN Device**: Cross-platform TUN support (Linux /dev/net/tun, macOS utun, Windows Wintun)
- **Pure Zig**: No C dependencies, compiles with Zig 0.13.0
- **Router**: Transparent proxy forwarding engine with libxev async I/O
- **SOCKS5 Proxy**: Built-in SOCKS5 client for TCP/UDP forwarding
- **NAT Support**: UDP session NAT translation for transparent proxy
- **Zero-Copy**: Pre-allocated buffers for optimal performance
- **Dual Stack**: IPv4 and IPv6 support

## Platform Support

| Platform | TUN Type     | Event Loop | Zero-Copy | Header  | Notes            |
| -------- | ------------ | ---------- | --------- | ------- | ---------------- |
| Linux    | /dev/net/tun | epoll      | Yes       | 0 bytes | Standard TUN/TAP |
| macOS    | utun socket  | kqueue     | Yes       | 4 bytes | AF_INET header   |
| Windows  | Wintun DLL   | IOCP       | Yes       | 0 bytes | Ring buffer I/O  |
| Android  | /dev/net/tun | epoll      | Yes       | 0 bytes | Same as Linux    |
| iOS      | utun socket  | kqueue     | Yes       | 4 bytes | Same as macOS    |

## Quick Start

### TUN Device

```zig
const tun = @import("tun");
const Options = tun.Options;

// Create TUN device options
const opts = tun.Options{
    .mtu = 1500,
    .network = .{
        .ipv4 = .{ .address = .{ 10, 0, 0, 1 }, .prefix = 24 },
    },
};

// Create the device
var device = try tun.create(std.heap.c_allocator, opts);
defer device.destroy();

// Read/write packets
var buf: [1500]u8 = undefined;
const n = try device.read(&buf);
try device.write(buf[0..n]);
```

### Router with SOCKS5 Proxy

```zig
const router = @import("router");

// Define routing callback
fn myRouteCallback(
    src_ip: u32,
    src_port: u16,
    dst_ip: u32,
    dst_port: u16,
    protocol: u8,
) router.RouteDecision {
    // Route decisions based on destination
    if (isPrivateIp(dst_ip)) return .Local;
    return .Socks5;  // Forward through SOCKS5 proxy
}

// Initialize router
var rt = try router.Router.init(allocator, .{
    .tun = .{
        .name = "tun0",
        .ifindex = if_nametoindex("tun0"),
        .ip = ip4(10, 0, 0, 1),
        .prefix_len = 24,
        .mtu = 1500,
        .fd = tun_fd,
    },
    .egress = .{
        .name = "en0",
        .ifindex = if_nametoindex("en0"),
        .ip = ip4(192, 168, 1, 100),
    },
    .proxy = .{
        .type = .Socks5,
        .addr = "127.0.0.1:1080",
    },
    .route_cb = myRouteCallback,
});
defer rt.deinit();

// Run event loop
rt.run();
```
