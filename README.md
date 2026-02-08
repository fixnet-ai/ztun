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

## macOS Usage Guide

### Prerequisites

- macOS 12.0 (Monterey) or later
- Zig 0.13.0
- Xcode Command Line Tools (`xcode-select --install`)

### Building

```bash
# Native macOS build (x86_64)
zig build tun2sock -Dtarget=x86_64-macos

# Apple Silicon build
zig build tun2sock -Dtarget=aarch64-macos

# Build with debug logging
sudo ./zig-out/bin/macos/tun2sock --tun-ip 10.0.0.1 --proxy 127.0.0.1:1080 -d
```

### Running

```bash
# Create TUN device and configure routes
sudo ./zig-out/bin/macos/tun2sock --tun-ip 10.0.0.1 --proxy 127.0.0.1:1080

# With verbose debug output
sudo ./zig-out/bin/macos/tun2sock --tun-ip 10.0.0.1 --proxy 127.0.0.1:1080 -d
```

### Route Configuration

ztun uses the C-based routing API (`route.h`) to configure system routes:

```c
// Route target IP to TUN device using C API
route_entry_t route = {
    .family = ROUTE_AF_INET,
    .ipv4.dst = target_ip,      // e.g., 111.45.11.5
    .ipv4.mask = 0xFFFFFFFF,   // /32 (single host)
    .ipv4.gateway = tun_ip,     // e.g., 10.0.0.1
    .iface_idx = tun_ifindex,
    .metric = 100,
};
route_add(&route);
```

### Testing ICMP (Ping)

```bash
# Test ICMP echo through TUN device
ping -I utunX 8.8.8.8

# Check interface
ifconfig utunX
```

## TUN Device Requirements

### Linux

- Access to `/dev/net/tun` (requires root or `cap_net_admin` capability)
- No additional kernel modules needed

### macOS

- utun interfaces are created automatically
- Requires 4-byte AF_INET header handling on read/write
- Use `ifconfig` or `route` commands to verify (or C API)

### Windows

- Wintun driver required (included in `/.windows/wintun/`)
- Administrator privileges required
- Ring buffer I/O for optimal performance

## SOCKS5 Proxy Configuration

### Basic Configuration

```bash
# Specify SOCKS5 proxy address
sudo ./zig-out/bin/macos/tun2sock --tun-ip 10.0.0.1 --proxy 192.168.1.1:1080
```

### Supported Features

- Connect command (TCP)
- UDP associate (UDP forwarding)
- No authentication (currently)

### Router Configuration

```zig
const router = @import("router");

// Route decisions based on destination IP
fn routeCallback(
    dst_ip: u32,
    protocol: u8,
) router.RouteDecision {
    const TARGET_IP = 0x6F2D0B05; // 111.45.11.5

    if (dst_ip == TARGET_IP) return .Socks5;
    if (isPrivateIp(dst_ip)) return .Local;
    return .Nat; // UDP goes through NAT
}
```

## Troubleshooting

### Common Issues

#### TUN Device Creation Failed

**Symptom**: `error.IoError` when creating TUN device

**Solution**:
```bash
# Check permissions
ls -la /dev/net/tun

# Load kernel module (Linux)
sudo modprobe tun

# Verify TUN support
cat /dev/net/tun
```

#### Route Configuration Failed

**Symptom**: `route_add()` returns -1

**Solution**:
```bash
# Check if route already exists
netstat -nr | grep <target_ip>

# Remove existing route first
sudo route delete <target_ip>

# Run with root privileges
sudo ./zig-out/bin/macos/tun2sock ...
```

#### ICMP Ping No Response

**Symptom**: Ping succeeds but no reply

**Solution**:
```bash
# Verify TUN device is up
ifconfig utunX

# Check routing table
netstat -nr | grep utunX

# Verify ICMP handler is running
./zig-out/bin/macos/tun2sock -d | grep ICMP
```

#### UDP NAT Not Working

**Symptom**: DNS queries timeout

**Solution**:
```bash
# Check NAT table
# (depends on NAT implementation)

# Verify egress interface
ifconfig en0 | grep inet

# Check firewall
sudo pfctl -s rules | grep udp
```

#### SOCKS5 Connection Failed

**Symptom**: TCP connections through proxy fail

**Solution**:
```bash
# Verify proxy is running
nc -zv 127.0.0.1 1080

# Test proxy directly
curl --socks5 127.0.0.1:1080 http://example.com

# Check proxy logs
```

### Debug Options

```bash
# Verbose debug output
-d, --debug      Enable debug logging
-v, --verbose    Verbose output (multiple times for more detail)

# Log levels
# 1: Basic info
# 2: Packet details
# 3: Full hex dumps
```

### Performance Tuning

```bash
# Increase MTU for better throughput
--mtu 1500

# Adjust NAT timeout
--nat-timeout 30

# Connection buffer size
--buffer-size 65535
```

## Build Targets

| Target | Command | Output |
|--------|---------|--------|
| x86_64-macos | `zig build -Dtarget=x86_64-macos` | `zig-out/bin/x86_64-macos/ztun` |
| aarch64-macos | `zig build -Dtarget=aarch64-macos` | `zig-out/bin/aarch64-macos/ztun` |
| x86_64-linux-gnu | `zig build -Dtarget=x86_64-linux-gnu` | `zig-out/bin/x86_64-linux-gnu/ztun` |
| x86_64-windows-gnu | `zig build -Dtarget=x86_64-windows-gnu` | `zig-out/bin/x86_64-windows-gnu/ztun.exe` |

## License

MIT
