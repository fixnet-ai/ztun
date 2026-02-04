# ztun Design Document

## Overview

ztun is a pure Zig TUN device library with transparent proxy forwarding capabilities. It provides three core components:

- **ztun.tun** - Cross-platform TUN device operations
- **ztun.ipstack** - Static IP protocol stack (TCP/UDP/ICMP)
- **ztun.router** - Transparent proxy forwarding engine with libxev async I/O

## Architecture

```
+---------------------------------------------------------------------+
|                     Application Layer                                |
|  (src/tun2sock.zig - Standalone TUN to SOCKS5 forwarding app)      |
+---------------------------------------------------------------------+
|                                                                     |
|  - Parses command line arguments                                    |
|  - Creates TUN device with provided name/IP                          |
|  - Detects egress interface                                        |
|  - Implements route callback for routing decisions                   |
|  - Passes all configuration to Router.init()                       |
+---------------------------------------------------------------------+
|                                                                     |
+---------------------------------------------------------------------+
|                     ztun.router Layer                                |
|  +-----------------------------------------------------------+     |
|  |  libxev Event Loop                                       |     |
|  |  - TUN async read (IO completion)                       |     |
|  |  - TUN async write (IO completion)                      |     |
|  |  - NAT cleanup timer (30s interval)                     |     |
|  +-----------------------------------------------------------+     |
|  +-----------------------------------------------------------+     |
|  |  Router Core Components                                  |     |
|  |  - Route callback interface (from application)           |     |
|  |  - NAT session table (UDP forwarding)                   |     |
|  |  - Packet buffer (64KB)                                 |     |
|  |  - Statistics tracking                                  |     |
|  +-----------------------------------------------------------+     |
|  +-----------------------------------------------------------+     |
|  |  Forwarding Handlers (stub implementations)              |     |
|  |  - forwardToEgress() - Raw socket forwarding            |     |
|  |  - forwardToProxy() - SOCKS5 proxy forwarding           |     |
|  |  - forwardWithNat() - UDP NAT translation                |     |
|  |  - writeToTun() - Local packet handling                 |     |
|  |  - handleIcmpEcho() - Ping response                     |     |
|  +-----------------------------------------------------------+     |
+---------------------------------------------------------------------+
|                     ztun.ipstack Layer                               |
|  - IPv4/IPv6 packet parsing (optional, for advanced use)           |
|  - TCP protocol (optional)                                          |
|  - UDP protocol (optional)                                          |
|  - ICMP echo handling                                               |
+---------------------------------------------------------------------+
|                     ztun.tun Layer                                  |
|  - Cross-platform TUN device (Linux/macOS/Windows)                  |
|  - DeviceBuilder for fluent API                                     |
|  - Packet send/recv                                                |
|  - MTU handling                                                    |
+---------------------------------------------------------------------+
```

## Key Design Principles

1. **Router is a FIXED forwarding engine** - No extension logic inside Router
2. **All configuration from application layer** - TUN params, egress, proxy, route callback
3. **Router doesn't create TUN or set system routes** - Application handles these
4. **Uses libxev for async I/O** - Zig 0.13.0 removed async/await syntax
5. **Zero-copy forwarding when possible** - Uses ringbuf for batch processing

## File Structure

```
ztun/
├── src/
│   ├── main.zig              # Library entry point (exports tun module)
│   ├── tun2sock.zig          # Standalone TUN to SOCKS5 forwarding app
│   ├── tun/                  # TUN device module
│   │   ├── mod.zig           # Main TUN interface
│   │   ├── builder.zig       # TUN device builder
│   │   ├── device.zig        # TUN device traits
│   │   ├── device_linux.zig  # Linux implementation
│   │   ├── device_macos.zig  # macOS implementation
│   │   ├── device_windows.zig # Windows implementation
│   │   └── ringbuf.zig       # Ring buffer for batch I/O
│   ├── ipstack/              # IP protocol stack (optional for forwarding)
│   │   ├── mod.zig           # IP stack entry
│   │   ├── checksum.zig      # Internet checksum
│   │   ├── ipv4.zig          # IPv4 parsing/generation
│   │   ├── ipv6.zig          # IPv6 parsing/generation
│   │   ├── tcp.zig           # TCP protocol
│   │   ├── udp.zig           # UDP protocol
│   │   ├── icmp.zig          # ICMP protocol
│   │   ├── connection.zig    # TCP connection tracking
│   │   └── callbacks.zig     # Protocol callbacks
│   └── router/               # Forwarding engine
│       ├── mod.zig           # Router main module (libxev integration)
│       ├── route.zig         # Route types and config
│       ├── nat.zig           # UDP NAT session table
│       └── proxy/
│           └── socks5.zig    # SOCKS5 protocol helpers
├── tests/
│   ├── test_framework.zig    # Shared test framework
│   ├── test_unit.zig         # Unit tests
│   └── test_runner.zig       # Integration tests
├── build.zig                  # Zig build script
├── build.zig.zon              # Build dependencies
└── DESIGN.md                 # This document
```

## Router Module

### Configuration

```zig
// TUN device configuration (from application)
pub const TunConfig = struct {
    name: [:0]const u8,      // TUN name (e.g., "tun0")
    ifindex: u32,            // Interface index
    ip: u32,                 // TUN IP (network byte order)
    prefix_len: u8,          // Prefix length (e.g., 24)
    mtu: u16,                // MTU size
    fd: std.posix.fd_t,      // TUN file descriptor
};

// Egress network interface (from application)
pub const EgressConfig = struct {
    name: [:0]const u8,      // Interface name (e.g., "en0")
    ifindex: u32,             // Interface index
    ip: u32,                  // Interface IP (network byte order)
};

// Proxy configuration (from application)
pub const ProxyType = enum {
    socks5,
    http,
};

pub const ProxyConfig = struct {
    type: ProxyType,          // .socks5 or .http
    addr: [:0]const u8,       // Proxy address (e.g., "127.0.0.1:1080")
    username: ?[:0]const u8, // Optional auth
    password: ?[:0]const u8, // Optional auth
};

// Complete router configuration
pub const RouterConfig = struct {
    tun: TunConfig,
    egress: EgressConfig,
    proxy: ?ProxyConfig,       // Optional proxy
    route_cb: RouteCallback,
    tcp_pool_size: usize = 4096,
    udp_nat_size: usize = 8192,
    idle_timeout: u32 = 300,
    udp_timeout: u32 = 30,
    nat_config: ?NatConfig = null,
};
```

### Route Decision

```zig
pub const RouteDecision = enum(u8) {
    Direct = 0,   // Forward through egress interface (bypasses TUN)
    Socks5 = 1,   // Forward through SOCKS5 proxy
    Drop = 2,     // Silently drop packet
    Local = 3,    // Handle locally (write back to TUN)
    Nat = 5,      // UDP NAT mode (rewrite source IP/port)
};

// Application implements this callback
pub const RouteCallback = *const fn (
    src_ip: u32,
    src_port: u16,
    dst_ip: u32,
    dst_port: u16,
    protocol: u8,
) RouteDecision;
```

### Route Example (from tun2sock.zig)

```zig
fn routeCallback(
    src_ip: u32,
    src_port: u16,
    dst_ip: u32,
    dst_port: u16,
    protocol: u8,
) router.RouteDecision {
    // Private IPs - handle locally
    if (isPrivateIp(dst_ip)) return .Local;

    // Multicast - drop
    if (isMulticast(dst_ip)) return .Drop;

    // UDP DNS - forward directly
    if (protocol == 17 and dst_port == 53) return .Direct;

    // UDP - use NAT
    if (protocol == 17) return .Nat;

    // TCP - go through SOCKS5
    return .Socks5;
}
```

## NAT Table

UDP forwarding requires NAT (Network Address Translation) for transparent proxy:

```
+---------------------------------------------------------------------+
|                    UDP NAT Forwarding Flow                          |
+---------------------------------------------------------------------+
|                                                                     |
|  Client (10.0.0.2)                  Router                         |
|       │                                 │                            |
|       │  UDP: src=10.0.0.2:12345      │                            |
|       │         dst=8.8.8.8:53        │                            |
|       ├────────────────────────────────►│                            |
|       │                                 │  Create NAT session       |
|       │                                 │  Rewrite source          |
|       │  UDP (rewritten):               │                            |
|       │  src= egress_ip:54321 ──────────┼────────────────────────►  │
|       │  dst=8.8.8.8:53               │                            |
|       │                                 │                            |
|       │                          Server (8.8.8.8)                    |
|       │                                 │                            |
|       │  Response:                      │                            |
|       │  src=8.8.8.8:53 ────────────────┼────────────────────────►  │
|       │  dst= egress_ip:54321          │                            |
|       │                                 │  Lookup NAT session       |
|       │  UDP (restored):               │  Restore source          |
|       │  src=8.8.8.8:53 ──────────────┼────────────────────────►  │
|       │  dst=10.0.0.2:12345           │                            |
|       │                                 │                            |
+---------------------------------------------------------------------+
```

### NAT Configuration

```zig
pub const NatConfig = struct {
    egress_ip: u32,              // NAT source IP (network byte order)
    port_range_start: u16 = 10000,  // Port range start
    port_range_end: u16 = 60000,    // Port range end
    timeout: u32 = 30,              // Session timeout (seconds)
};
```

### NAT Table Implementation

The NAT table uses open addressing hash table with linear probing:

- **lookup()** - O(1) average lookup by 4-tuple
- **insert()** - O(1) average insert with port allocation
- **remove()** - O(1) average remove by 4-tuple
- **reverseLookup()** - O(n) lookup by mapped port (for response packets)
- **cleanup()** - Remove expired sessions (called every 30s)

## libxev Integration

Zig 0.13.0 removed async/await syntax. We use libxev callback-based async I/O:

```zig
const xev = @import("xev");

pub const Router = struct {
    /// libxev event loop
    loop: xev.Loop,

    /// libxev completion for TUN reading
    tun_completion: xev.Completion,

    /// libxev completion for TUN writing
    tun_write_completion: xev.Completion,

    /// libxev timer for NAT cleanup
    nat_timer: xev.Completion,

    /// Configuration
    config: RouterConfig,

    /// NAT session table (for UDP forwarding)
    nat_table: ?*NatTable,

    /// Current state
    state: RouterState,

    /// Packet buffer for TUN reads (64KB)
    packet_buf: [65536]u8,

    /// Write buffer for TUN writes (64KB)
    write_buf: [65536]u8,

    /// Statistics
    _stats: RouterStats,

    /// Memory allocator
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, config: RouterConfig) !Router {
        // Initialize NAT table if configured
        var nat_table: ?*NatTable = null;
        if (config.nat_config) |nat_cfg| {
            nat_table = try NatTable.init(allocator, nat_cfg, config.udp_nat_size);
        }

        // Create libxev loop
        return .{
            .loop = try xev.Loop.init(.{}),
            .tun_completion = .{},
            .tun_write_completion = .{},
            .nat_timer = .{},
            .config = config,
            .nat_table = nat_table,
            .state = .init,
            .packet_buf = undefined,
            .write_buf = undefined,
            ._stats = .{},
            .allocator = allocator,
        };
    }

    pub fn run(router: *Router) void {
        router.state = .running;

        // Submit initial TUN read
        router.submitTunRead();

        // Submit NAT cleanup timer if configured
        if (router.config.nat_config != null) {
            router.submitNatTimer();
        }

        // Run event loop
        router.loop.run(.until_done) catch {};
        router.state = .stopped;
    }
};

/// TUN readable callback (libxev)
fn onTunReadable(
    userdata: ?*anyopaque,
    loop: *xev.Loop,
    completion: *xev.Completion,
    result: xev.Result,
) xev.CallbackAction {
    const router = @as(*Router, @ptrCast(@alignCast(userdata orelse return .disarm)));

    // Handle read result
    const n = result.read catch {
        router.submitTunRead();
        return .disarm;
    };

    router._stats.bytes_rx += n;

    // Check if ICMP - handle echo immediately
    if (protocol == 1) {
        router.handleIcmpEcho(header_len) catch {};
        router.submitTunRead();
        return .disarm;
    }

    // Parse and forward packet
    const packet = router.parsePacket(router.packet_buf[0..n]) catch {
        router.submitTunRead();
        return .disarm;
    };

    router.forwardPacket(&packet) catch {};
    router.submitTunRead();
    return .disarm;
}

/// NAT cleanup timer callback
fn onNatTimer(
    userdata: ?*anyopaque,
    loop: *xev.Loop,
    completion: *xev.Completion,
    result: xev.Result,
) xev.CallbackAction {
    const router = @as(*Router, @ptrCast(@alignCast(userdata orelse return .disarm)));

    _ = result.timer catch {
        router.submitNatTimer();
        return .disarm;
    };

    // Cleanup expired NAT sessions
    if (router.config.nat_config != null) {
        _ = router.nat_table.?.cleanup();
    }

    router.submitNatTimer();
    return .disarm;
}
```

## Platform Support

| Platform | TUN | Event Loop | Zero-Copy | Notes |
|----------|-----|------------|-----------|-------|
| Linux | Yes | epoll | Yes | Uses /dev/net/tun |
| macOS | Yes | kqueue | Yes | Uses utun sockets |
| Windows | Yes | IOCP | Yes | Uses Wintun |
| Android | Yes | epoll | Yes | Same as Linux |
| iOS | Yes | kqueue | Yes | Same as macOS |

## tun2sock Application

The `src/tun2sock.zig` is a standalone TUN to SOCKS5 forwarding application:

```bash
# Build
zig build tun2sock

# Run (requires root)
sudo ./zig-out/bin/macos/tun2sock --tun-name tun0 --tun-ip 10.0.0.1 --proxy 127.0.0.1:1080
```

### Command Line Options

| Option | Short | Default | Description |
|--------|-------|---------|-------------|
| --tun-name | -n | tun0 | TUN device name |
| --tun-ip | -i | 10.0.0.1 | TUN interface IP |
| --tun-mtu | -m | 1500 | TUN device MTU |
| --prefix | -p | 24 | IPv4 prefix length |
| --proxy | -x | 127.0.0.1:1080 | SOCKS5 proxy address |
| --egress | -e | (auto) | Egress interface name |
| --debug | -d | off | Enable debug logging |

## Performance Characteristics

| Operation | Complexity | Notes |
|-----------|------------|-------|
| Route lookup | O(1) avg | Via application callback |
| NAT session find | O(1) avg | Open addressing hash |
| Packet parsing | O(1) | Fixed offset extraction |
| ICMP echo | O(1) | Immediate response |

## Default Capacities

| Resource | Default | Max | Use Case |
|----------|---------|-----|----------|
| TCP connections | 4096 | 65536 | Web browsing |
| UDP NAT sessions | 8192 | 65536 | DNS, gaming, VoIP |
| Packet buffer | 64KB | 64KB | Single packet |
| NAT table size | 8192 | 65536 | Hash slots |

## Build Commands

```bash
# Build native library and run unit tests
zig build

# Build and run integration tests
zig build test

# Build tun2sock application
zig build tun2sock

# Build all platform static libraries
zig build all

# Cross-compile to specific target
zig build -Dtarget=x86_64-linux-gnu
zig build -Dtarget=aarch64-macos
```

## Usage Example

```zig
// Create router with configuration
var router = try router.Router.init(allocator, .{
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
        .type = .socks5,
        .addr = "127.0.0.1:1080",
    },
    .route_cb = myRouteCallback,
    .nat_config = .{
        .egress_ip = ip4(192, 168, 1, 100),
        .port_range_start = 10000,
        .port_range_end = 60000,
    },
});
defer router.deinit();

// Run event loop (blocking)
router.run();
```
