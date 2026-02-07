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

## Build Commands

```bash
zig build              # Build native library + run unit tests
zig build test         # Build test_runner to bin/macos/ (requires sudo)
zig build all          # Build static libraries for all targets to lib/{target}/
zig build all-tests    # Build test_runner for all targets to bin/{target}/
```

### Output Structure

```
zig-out/
├── lib/                    # Static libraries by platform
│   ├── x86_64-linux-gnu/libztun.a
│   ├── x86_64-windows-gnu/ztun.lib
│   ├── aarch64-macos/libztun.a
│   └── ...
└── bin/                    # Test executables by platform
    ├── x86_64-linux-gnu/ztun_test_runner
    ├── x86_64-windows-gnu/ztun_test_runner.exe
    ├── x86_64-macos/ztun_test_runner
    └── ...
```

## Multi-Platform Testing

### macOS (Native)

```bash
sudo ./zig-out/bin/macos/ztun_test_runner
```

### Linux (Lima VM)

```bash
# Build for Linux
zig build -Dtarget=x86_64-linux-gnu

# Run on Lima VM (via shared directory)
.lima/lima-exec.sh sudo /Users/modasi/works/2025/fixnet/ztun/zig-out/bin/x86_64-linux-gnu/ztun_test_runner
```

### Windows VM

```bash
# Deploy to Windows VM
.windows/windows-deploy.sh

# Run on Windows VM
.windows/windows-exec.sh
```

## macOS Notes

On macOS, TUN devices are created as utun interfaces. Due to macOS kernel restrictions:

1. **IP Configuration**: The `ifconfig` command must be used to configure IP addresses:

   ```bash
   sudo ifconfig utunX 10.0.0.1 10.0.0.2
   ```

2. **No ioctl Support**: SIOCSIFADDR/SIOCSIFDSTADDR ioctl calls fail for utun interfaces. The library silently ignores these errors.

3. **Routing**: For ping 10.0.0.2 to work, the interface must be configured with both local and peer IP addresses.

## Directory Structure

```
ztun/
├── src/
│   ├── main.zig              # Library entry point (exports public API)
│   ├── tun2sock.zig          # Standalone TUN to SOCKS5 forwarding app
│   ├── tun/                  # TUN device module
│   │   ├── mod.zig           # Main module (exports, imports)
│   │   ├── options.zig       # TUN configuration options
│   │   ├── device.zig        # TunDevice/DeviceOps interfaces & Device type
│   │   ├── device_linux.zig  # Linux/Android implementation
│   │   ├── device_darwin.zig # macOS/iOS implementation
│   │   ├── device_windows.zig # Windows implementation
│   │   ├── device_ios.zig    # iOS PacketFlow wrapper
│   │   ├── tun_stack.zig         # TunStack interface
│   │   └── handler.zig       # PacketHandler interface
│   │
│   ├── router/               # Forwarding engine
│   │   ├── mod.zig           # Router with libxev async I/O
│   │   ├── route.zig         # Route types and configuration
│   │   ├── nat.zig           # UDP NAT session table
│   │   └── proxy/
│   │       └── socks5.zig    # SOCKS5 protocol helpers
│   │
│   ├── ipstack/              # Pure Zig IP stack
│   │   ├── mod.zig           # IP stack entry
│   │   ├── checksum.zig      # Internet checksum
│   │   ├── ipv4.zig          # IPv4 header parsing/building
│   │   ├── ipv6.zig          # IPv6 header parsing/building
│   │   ├── tcp.zig           # TCP protocol utilities
│   │   ├── udp.zig           # UDP protocol utilities
│   │   ├── icmp.zig          # ICMP protocol utilities
│   │   ├── connection.zig    # TCP connection state machine
│   │   └── callbacks.zig     # Callback interface definitions
│   │
│   └── system/               # System utilities
│       └── sysroute.zig      # Routing table management
│
├── tests/
│   ├── test_unit.zig         # Unit tests (Zig test blocks)
│   ├── test_runner.zig      # Integration tests (executable)
│   └── test_tun.zig         # Ping echo test
│
├── docs/
│   └── DESIGN.md            # Architecture documentation
│
├── build.zig                 # Zig build script
└── README.md                 # This file
```

## API Reference

### TUN Module

**Options:**

```zig
const Options = struct {
    mtu: ?u16 = null,
    network: ?NetworkConfig = null,
    packet_info: bool = false,
    gso: bool = false,
    fd: ?std.posix.fd_t = null,
    dns: ?DnsConfig = null,
    routes: ?RouteConfig = null,
};

const NetworkConfig = struct {
    ipv4: ?Ipv4Network = null,
    ipv6: ?Ipv6Network = null,
};
```

**TunDevice:**

- `read(buf: []u8) !usize` - Read a packet from TUN
- `write(buf: []const u8) !usize` - Write a packet to TUN
- `fd() fd_t` - Get file descriptor
- `destroy()` - Destroy device and release resources

**DeviceOps:**

- `read(buf: []u8) !usize` - Read with function pointer
- `write(buf: []const u8) !usize` - Write with function pointer
- `fd() fd_t` - Get file descriptor
- `destroy()` - Destroy device

### Router Module

**TunConfig:**

```zig
const TunConfig = struct {
    name: [:0]const u8,
    ifindex: u32,
    ip: u32,
    prefix_len: u8,
    mtu: u16,
    fd: std.posix.fd_t,
    device_ops: ?*const DeviceOps = null,
    header_len: usize = 0,  // 4 for macOS, 0 for Linux/Windows
};
```

**RouteDecision:**

- `.Direct` - Forward through raw socket
- `.Socks5` - Forward through SOCKS5 proxy
- `.Nat` - UDP NAT mode
- `.Local` - Handle locally (write back to TUN)
- `.Drop` - Silently drop

**Router:**

- `init(allocator, config) !Router` - Initialize router
- `run() void` - Run event loop (blocking)
- `deinit() void` - Cleanup resources
