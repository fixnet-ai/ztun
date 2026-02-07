# ztun Design Document

## Overview

ztun is a pure Zig TUN device library with transparent proxy forwarding capabilities. It provides four core components:

- **ztun.tun** - Cross-platform TUN device operations
- **ztun.ipstack** - Static IP protocol stack (TCP/UDP/ICMP)
- **ztun.router** - Transparent proxy forwarding engine with libxev async I/O
- **ztun.network** - Cross-platform routing and network interface management

## Architecture

```
+---------------------------------------------------------------------+
|                     Application Layer                                |
|  (src/tun2sock.zig - Standalone TUN to SOCKS5 forwarding app)      |
+---------------------------------------------------------------------+
|                                                                     |
|  - Parses command line arguments                                    |
|  - Creates TUN device with DeviceBuilder                             |
|  - Detects egress interface using network module                   |
|  - Implements route callback for routing decisions                  |
|  - Implements isElevated() privilege check                          |
|  - Passes all configuration to Router.init()                       |
+---------------------------------------------------------------------+
|                                                                     |
+---------------------------------------------------------------------+
|                     ztun.router Layer                                |
|  +-----------------------------------------------------------+     |
|  |  libxev Event Loop                                       |     |
|  |  - TUN async read (IO completion)                         |     |
|  |  - TUN async write (IO completion)                       |     |
|  |  - TCP async connect (IO completion)                     |     |
|  |  - UDP async send/recv (IO completion)                  |     |
|  |  - NAT cleanup timer (30s interval)                      |     |
|  +-----------------------------------------------------------+     |
|  +-----------------------------------------------------------+     |
|  |  Router Core Components                                  |     |
|  |  - Route callback interface (from application)           |     |
|  |  - NAT session table (UDP forwarding)                   |     |
|  |  - SOCKS5 proxy connection manager                      |     |
|  |  - Raw socket for direct forwarding                     |     |
|  |  - UDP socket for NAT forwarding                        |     |
|  |  - Packet buffer (64KB)                                 |     |
|  |  - Statistics tracking                                  |     |
|  +-----------------------------------------------------------+     |
|  +-----------------------------------------------------------+     |
|  |  Forwarding Handlers                                     |     |
|  |  - forwardToEgress() - Raw socket forwarding             |     |
|  |  - forwardToProxy() - SOCKS5 TCP forwarding             |     |
|  |  - forwardWithNat() - UDP NAT translation               |     |
|  |  - writeToTun() - Local packet handling                 |     |
|  |  - handleIcmpEcho() - Ping response                     |     |
|  +-----------------------------------------------------------+     |
+---------------------------------------------------------------------+
|                     ztun.ipstack Layer                               |
|  - IPv4/IPv6 packet parsing (checksum module)                       |
|  - TCP protocol (optional)                                         |
|  - UDP protocol (optional)                                         |
|  - ICMP echo handling                                             |
+---------------------------------------------------------------------+
|                     ztun.tun Layer                                  |
|  - Cross-platform TUN device (Linux/macOS/Windows/Android/iOS)      |
|  - DeviceBuilder for fluent API                                    |
|  - Device.createFromFd() for Android VpnService                    |
|  - Packet send/recv                                               |
|  - MTU handling                                                   |
+---------------------------------------------------------------------+
|                     ztun.network Layer                             |
|  - Cross-platform routing and network interface management           |
|  - Native system APIs (netlink/RoutingSockets/IP Helper)           |
|  - getLocalIps() for all platforms                                  |
|  - getPrimaryIp() to probe egress IP                                |
|  - Route add/delete operations                                      |
+---------------------------------------------------------------------+
```

## Key Design Principles

1. **Router is a FIXED forwarding engine** - No extension logic inside Router
2. **All configuration from application layer** - TUN params, egress, proxy, route callback
3. **Router doesn't create TUN or set system routes** - Application handles these
4. **Uses libxev for async I/O** - Zig 0.13.0 removed async/await syntax
5. **Egress traffic bypasses TUN** - Uses raw socket with SO_BINDTODEVICE

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
│   │   ├── platform.zig      # Platform detection
│   │   └── ringbuf.zig       # Ring buffer for batch I/O
│   ├── ipstack/              # IP protocol stack (for checksum only)
│   │   ├── mod.zig           # IP stack entry
│   │   ├── checksum.zig      # Internet checksum
│   │   ├── ipv4.zig          # IPv4 parsing/generation
│   │   ├── ipv6.zig          # IPv6 parsing/generation
│   │   ├── tcp.zig           # TCP protocol
│   │   ├── udp.zig           # UDP protocol
│   │   ├── icmp.zig          # ICMP protocol
│   │   ├── connection.zig    # TCP connection tracking
│   │   └── callbacks.zig     # Protocol callbacks
│   ├── router/               # Forwarding engine
│   │   ├── mod.zig           # Router main module (libxev integration)
│   │   ├── route.zig         # Route types and config
│   │   ├── nat.zig           # UDP NAT session table
│   │   └── proxy/
│   │       └── socks5.zig    # SOCKS5 protocol helpers
│   └── system/               # System utilities
│       └── network.zig      # Routing and network interface management
├── tests/
│   ├── test_framework.zig    # Shared test framework
│   ├── test_unit.zig         # Unit tests
│   └── test_runner.zig       # Integration tests
├── build.zig                 # Zig build script
├── build.zig.zon             # Build dependencies
└── DESIGN.md                 # This document
```

## Router Module

### Configuration

```zig
// TUN device configuration (from application)
pub const TunConfig = struct {
    name: [:0]const u8,       // TUN name (auto-generated on macOS)
    ifindex: u32,             // Interface index
    ip: u32,                  // TUN IP (network byte order)
    prefix_len: u8,           // Prefix length (e.g., 24)
    mtu: u16,                 // MTU size
    fd: std.posix.fd_t,       // TUN file descriptor
};

// Egress network interface (from application)
pub const EgressConfig = struct {
    name: [:0]const u8,       // Interface name (e.g., "en0")
    ifindex: u32,             // Interface index
    ip: u32,                  // Interface IP (network byte order)
};

// Proxy protocol type
pub const ProxyType = enum(u8) {
    None = 0,
    Socks5 = 1,
    Http = 2,
    Https = 3,
};

pub const ProxyConfig = struct {
    type: ProxyType,           // Proxy type
    addr: [:0]const u8,       // Proxy address (e.g., "127.0.0.1:1080")
    username: ?[:0]const u8,  // Optional auth
    password: ?[:0]const u8,  // Optional auth
};

// Complete router configuration
pub const RouterConfig = struct {
    tun: TunConfig,
    egress: EgressConfig,
    proxy: ?ProxyConfig,        // Optional proxy
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
    Direct = 0,   // Forward through egress (raw socket)
    Socks5 = 1,   // Forward through SOCKS5 proxy
    Http = 2,     // Forward through HTTP proxy
    Drop = 3,     // Silently drop packet
    Local = 4,    // Handle locally (write back to TUN)
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
|                    UDP NAT Forwarding Flow                           |
+---------------------------------------------------------------------+
|                                                                     |
|  Client (10.0.0.2)                  Router                          |
|       │                                 │                             |
|       │  UDP: src=10.0.0.2:12345      │                             |
|       │         dst=8.8.8.8:53        │                             |
|       ├────────────────────────────────►│                             |
|       │                                 │  Create NAT session          |
|       │                                 │  Rewrite source            |
|       │  UDP (rewritten):              │                             |
|       │  src= egress_ip:54321 ─────────┼─────────────────────────►   │
|       │  dst=8.8.8.8:53               │                             |
|       │                                 │                             |
|       │                            Server (8.8.8.8)                  |
|       │                                 │                             |
|       │  Response:                      │                             |
|       │  src=8.8.8.8:53 ──────────────┼─────────────────────────►   │
|       │  dst= egress_ip:54321          │                             |
|       │                                 │  Lookup NAT session         |
|       │  UDP (restored):               │  Restore source            |
|       │  src=8.8.8.8:53 ──────────────┼─────────────────────────►   │
|       │  dst=10.0.0.2:12345           │                             |
|       │                                 │                             |
+---------------------------------------------------------------------+
```

### NAT Configuration

```zig
pub const NatConfig = struct {
    egress_ip: u32,             // NAT source IP (network byte order)
    port_range_start: u16 = 10000,  // Port range start
    port_range_end: u16 = 60000,    // Port range end
    timeout: u32 = 30,          // Session timeout (seconds)
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

    /// libxev completion for SOCKS5 TCP
    socks5_completion: xev.Completion,

    /// libxev completion for UDP socket
    udp_completion: xev.Completion,

    /// libxev timer for NAT cleanup
    nat_timer: xev.Completion,

    /// Configuration
    config: RouterConfig,

    /// NAT session table (for UDP forwarding)
    nat_table: ?*NatTable,

    /// SOCKS5 proxy connection (shared for all TCP)
    socks5_conn: ?*Socks5Conn,

    /// UDP socket for NAT forwarding
    udp_sock: ?std.posix.socket_t = null,

    /// Raw socket for direct packet forwarding
    raw_sock: ?std.posix.socket_t = null,

    /// UDP send buffer
    udp_send_buf: [65536]u8 = undefined,

    /// UDP recv buffer
    udp_recv_buf: [65536]u8 = undefined,

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

        // Create SOCKS5 connection if proxy is configured
        var socks5_conn_ptr: ?*Socks5Conn = null;
        if (config.proxy) |proxy| {
            const conn = try allocator.create(Socks5Conn);
            conn.* = .{
                .allocator = allocator,
                .state = .Disconnected,
                .sock = null,
            };
            socks5_conn_ptr = conn;
        }

        // Create UDP socket for NAT forwarding
        var udp_sock: ?std.posix.socket_t = null;
        if (config.nat_config != null) {
            udp_sock = std.posix.socket(AF_INET, SOCK_DGRAM, 0) catch null;
        }

        // Create raw socket for direct packet forwarding
        var raw_sock: ?std.posix.socket_t = null;
        raw_sock = std.posix.socket(AF_INET, SOCK_RAW, IPPROTO_RAW) catch null;

        // Create libxev loop
        return .{
            .loop = try xev.Loop.init(.{}),
            .tun_completion = .{},
            .tun_write_completion = .{},
            .nat_timer = .{},
            .socks5_completion = .{},
            .udp_completion = .{},
            .config = config,
            .nat_table = nat_table,
            .socks5_conn = socks5_conn_ptr,
            .udp_sock = udp_sock,
            .raw_sock = raw_sock,
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
    const ver_ihl = router.packet_buf[0];
    const ihl = ver_ihl & 0x0F;
    const header_len = @as(usize, ihl) * 4;
    const protocol = router.packet_buf[9];

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

### Router Statistics

```zig
pub const RouterStats = struct {
    tcp_connections: u64 = 0,
    udp_sessions: u64 = 0,
    packets_forwarded: u64 = 0,
    packets_dropped: u64 = 0,
    bytes_rx: u64 = 0,
    bytes_tx: u64 = 0,
};
```

## SOCKS5 Proxy Implementation

The router includes a complete SOCKS5 proxy client implementation:

```zig
const Socks5ConnState = enum(u8) {
    Disconnected = 0,
    Connecting = 1,
    Greeting = 2,
    ConnectRequest = 3,
    Ready = 4,
    Error = 5,
};

const Socks5Conn = struct {
    state: Socks5ConnState = .Disconnected,
    sock: ?std.posix.socket_t = null,
    dst_ip: u32 = 0,
    dst_port: u16 = 0,
    allocator: std.mem.Allocator,
    read_buf: [65536]u8 = undefined,
    read_offset: usize = 0,
    write_buf: [65536]u8 = undefined,
    write_offset: usize = 0,
    proxy_ip: u32 = 0,
    proxy_port: u16 = 0,
};
```

## Platform Support

| Platform | TUN | Event Loop | Zero-Copy | Notes |
|----------|-----|------------|-----------|-------|
| Linux | Yes | epoll | Yes | Uses /dev/net/tun |
| macOS | Yes | kqueue | Yes | Uses utun sockets |
| Windows | Yes | IOCP | Yes | Uses Wintun |
| Android | Yes | epoll | Yes | Same as Linux + createFromFd |
| iOS | Yes | kqueue | Yes | Same as macOS + createFromFd |

## network Module

Cross-platform routing and network interface management using native system APIs (C implementation):

**Architecture:**

```
src/system/
├── network.c      # C implementation (platform detection, getifaddrs, netlink, routing sockets)
├── network.h     # C header with route_entry_t struct and public API
└── network.zig   # Zig FFI wrapper with RouteEntry, utility functions
```

**C API (network.c):**

| Function | Platform | Description |
|----------|----------|-------------|
| `get_local_ips()` | All | Get all local IP addresses using getifaddrs/GetAdaptersAddresses |
| `get_primary_ip()` | All | Probe primary egress IP via UDP socket |
| `select_egress_ip_for_target()` | All | Find best egress IP for specific target |
| `route_add()` | All | Add route via netlink/RoutingSockets/IPHelper |
| `route_delete()` | All | Delete route via netlink/RoutingSockets/IPHelper |
| `route_list()` | All | Query routing table |
| `route_get_iface_index()` | All | Get interface index by name |

**Platform-specific implementations:**

| Platform | Routing API | Network Interface API |
|----------|-------------|----------------------|
| Linux | netlink (NETLINK_ROUTE) | getifaddrs() |
| macOS/iOS | BSD routing sockets (PF_ROUTE) | getifaddrs() |
| Windows | IP Helper API (iphlpapi.dll) | GetAdaptersAddresses() |

**Zig wrapper (network.zig):**

```zig
pub const RouteEntry = extern struct {
    family: RouteAddressFamily,
    un: extern union {
        ipv4: RouteIpv4,
        ipv6: RouteIpv6,
    },
    iface_idx: u32,
    metric: c_int,
};

/// Add single route
pub fn addRoute(route: *const RouteEntry) !void;

/// Delete single route
pub fn deleteRoute(route: *const RouteEntry) !void;

/// Query routing table
pub fn listRoutes(alloc: std.mem.Allocator) ![]RouteEntry;

/// Get all local IP addresses
pub fn getLocalIps(alloc: std.mem.Allocator) ![]IpInfo;

/// Get primary egress IP
pub fn getPrimaryIp(alloc: std.mem.Allocator) ![]u8;
```

## tun2sock Application

The `src/tun2sock.zig` is a standalone TUN to SOCKS5 forwarding application:

```bash
# Build
zig build tun2sock

# Run (requires root)
sudo ./zig-out/bin/macos/tun2sock --tun-ip 10.0.0.1 --proxy 127.0.0.1:1080 --egress en0
```

### Command Line Options

| Option | Short | Default | Description |
|--------|-------|---------|-------------|
| --tun-ip | -i | 10.0.0.1 | TUN interface IP |
| --tun-mtu | -m | 1500 | TUN device MTU |
| --prefix | -p | 24 | IPv4 prefix length |
| --proxy | -x | 127.0.0.1:1080 | SOCKS5 proxy address |
| --egress | -e | en0 | Egress interface name |
| --debug | -d | off | Enable debug logging |

### Privilege Check

```zig
fn isElevated() bool {
    if (builtin.os.tag == .windows) {
        return IsUserAnAdmin() != 0;
    }
    return geteuid() == 0;
}
```

## Performance Characteristics

| Operation | Complexity | Notes |
|-----------|------------|-------|
| Route lookup | O(1) avg | Via application callback |
| NAT session find | O(1) avg | Open addressing hash |
| Packet parsing | O(1) | Fixed offset extraction |
| ICMP echo | O(1) | Immediate response |
| Raw socket forward | O(1) | Single syscall |

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

# Android builds
zig build android-test
zig build android-runner

# iOS Simulator builds
zig build ios-test
zig build ios-runner
```

## Usage Example

```zig
const router = @import("router");

// Application defines routing callback
fn myRouteCallback(
    src_ip: u32,
    src_port: u16,
    dst_ip: u32,
    dst_port: u16,
    protocol: u8,
) router.RouteDecision {
    if (isPrivateIp(dst_ip)) return .Local;
    return .Socks5;
}

// Create router with configuration
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
    .nat_config = .{
        .egress_ip = ip4(192, 168, 1, 100),
        .port_range_start = 10000,
        .port_range_end = 60000,
    },
});
defer rt.deinit();

// Run event loop (blocking)
rt.run();
```
