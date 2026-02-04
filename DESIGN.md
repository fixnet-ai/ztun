# ztun Design Document

## Overview

ztun is a pure Zig TUN device library with transparent proxy forwarding capabilities. It provides three core components:

- **ztun.tun** - Cross-platform TUN device operations
- **ztun.ipstack** - Static IP protocol stack (TCP/UDP/ICMP)
- **ztun.router** - Transparent proxy forwarding engine

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Application Layer                        │
│  (tests/tun2sock.zig - uses zinternal app framework)        │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  - Parses command line arguments                            │
│  - Creates TUN device with provided name/IP                 │
│  - Detects egress interface                                 │
│  - Implements route callback for routing decisions          │
│  - Passes all configuration to Router.init()               │
│                                                             │
├─────────────────────────────────────────────────────────────┤
│                     ztun.router Layer                        │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  libxev Event Loop                                 │   │
│  │  - TUN async read                                  │   │
│  │  - TCP async connect                               │   │
│  │  - UDP NAT session timeout                         │   │
│  └─────────────────────────────────────────────────────┘   │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  Router Core Components                            │   │
│  │  - Route callback interface                        │   │
│  │  - TCP connection pool                            │   │
│  │  - UDP NAT session table                          │   │
│  │  - Proxy forwarder (SOCKS5/HTTP)                  │   │
│  └─────────────────────────────────────────────────────┘   │
├─────────────────────────────────────────────────────────────┤
│                     ztun.ipstack Layer                       │
│  - IPv4/IPv6 packet parsing                                │
│  - TCP state machine                                      │
│  - UDP socket handling                                    │
│  - ICMP echo handling                                     │
├─────────────────────────────────────────────────────────────┤
│                     ztun.tun Layer                          │
│  - Cross-platform TUN device (Linux/macOS/Windows)         │
│  - Packet send/recv                                       │
│  - MTU handling                                           │
└─────────────────────────────────────────────────────────────┘
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
│   ├── main.zig              # Library entry point
│   ├── tun/                   # TUN device module
│   │   ├── mod.zig           # Main TUN interface
│   │   ├── builder.zig       # TUN device builder
│   │   ├── device.zig        # TUN device traits
│   │   ├── device_linux.zig  # Linux implementation
│   │   ├── device_macos.zig  # macOS implementation
│   │   ├── device_windows.zig # Windows implementation
│   │   └── ringbuf.zig       # Ring buffer for batch I/O
│   ├── ipstack/              # IP protocol stack
│   │   ├── mod.zig           # IP stack entry
│   │   ├── checksum.zig     # Internet checksum
│   │   ├── ipv4.zig          # IPv4 parsing/generation
│   │   ├── ipv6.zig          # IPv6 parsing/generation
│   │   ├── tcp.zig           # TCP protocol
│   │   ├── udp.zig           # UDP protocol
│   │   ├── icmp.zig          # ICMP protocol
│   │   ├── connection.zig    # TCP connection tracking
│   │   └── callbacks.zig     # Protocol callbacks
│   └── router/               # Forwarding engine
│       ├── mod.zig           # Router main module
│       ├── route.zig         # Route types and config
│       ├── nat.zig           # UDP NAT session table
│       └── proxy/
│           ├── socks5.zig    # SOCKS5 backend
│           └── http.zig       # HTTP backend (planned)
├── tests/
│   ├── test_unit.zig         # Unit tests
│   ├── test_runner.zig       # Integration tests
│   └── tun2sock.zig          # TUN to SOCKS5 forwarding app
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

### Route Example

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
┌─────────────────────────────────────────────────────────────┐
│                    UDP NAT Forwarding Flow                  │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Client (10.0.0.2)                  Router                 │
│       │                                 │                    │
│       │  UDP: src=10.0.0.2:12345      │                    │
│       │         dst=8.8.8.8:53        │                    │
│       ├────────────────────────────────►│                    │
│       │                                 │  Create NAT session│
│       │                                 │  Rewrite source    │
│       │  UDP (rewritten):               │                    │
│       │  src= egress_ip:54321 ──────────┼─────────────────►  │
│       │  dst=8.8.8.8:53               │                    │
│       │                                 │                    │
│       │                          Server (8.8.8.8)            │
│       │                                 │                    │
│       │  Response:                      │                    │
│       │  src=8.8.8.8:53 ────────────────┼─────────────────►  │
│       │  dst= egress_ip:54321          │                    │
│       │                                 │  Lookup NAT session│
│       │  UDP (restored):               │  Restore source    │
│       │  src=8.8.8.8:53 ──────────────┼─────────────────►  │
│       │  dst=10.0.0.2:12345           │                    │
│       │                                 │                    │
└─────────────────────────────────────────────────────────────┘
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

## SOCKS5 Proxy

### Protocol Flow

```
┌─────────────────────────────────────────────────────────────┐
│                    SOCKS5 Protocol Flow                      │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  1. Client sends greeting:                                   │
│     +----+------+-------+                                    │
│     | VER | NMETH | METHODS |                               │
│     +----+------+-------+                                    │
│     | 05  |   1   |   00   |  (no auth)                     │
│     +----+------+-------+                                    │
│                                                             │
│  2. Server selects auth method:                              │
│     +----+-------+                                           │
│     | VER | METHOD |                                         │
│     +----+-------+                                           │
│     | 05 |   00   |  (no auth accepted)                     │
│     +----+-------+                                           │
│                                                             │
│  3. Client sends connect request:                           │
│     +----+-----+------+------+------+------+                 │
│     | VER | CMD |  RSV  | ATYP | BND.ADDR | BND.PORT |      │
│     +----+-----+------+------+------+------+                 │
│     | 05 |  01  |  00  |  01  |  IP:port  |              │
│     +----+-----+------+------+------+------+                 │
│                                                             │
│  4. Server responds:                                        │
│     +----+-----+------+------+------+------+                 │
│     | VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |      │
│     +----+-----+------+------+------+------+                 │
│     | 05 |  00  |  00  |  01  |  IP:port  |              │
│     +----+-----+------+------+------+------+                 │
│                                                             │
│  5. Forward data (both directions)                          │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Usage

```zig
// Create SOCKS5 connection
const conn = try socks5Connect(proxy_addr, proxy_port);

// Build connect request
var buf: [256]u8 = undefined;
const req_len = buildConnectRequest(&buf, dst_ip, dst_port);

// Send/receive data
const sent = try socks5Send(conn, buf[0..req_len]);
```

## libxev Integration

Zig 0.13.0 removed async/await syntax. We use libxev callback-based async I/O:

```zig
const libxev = @import("libxev");

pub const Router = struct {
    loop: *libxev.Loop,
    tun_io: libxev.IO,
    tcp_pool: TcpPool,
    nat_table: NatTable,
    config: RouterConfig,

    pub fn init(config: RouterConfig) !*Router {
        const loop = libxev.Loop.new(.{});

        // Submit TUN read to event loop
        loop.io(&tun_io, config.tun.fd, .readable, onTunReadable, null);

        return // ...
    }
};

fn onTunReadable(self: *libxev.IO, revents: u32) void {
    const router = @as(*Router, @ptrCast(self.userdata orelse return));

    // Read packet from TUN
    const n = std.posix.read(config.tun.fd, &buffer);

    // Parse IP header, extract 4-tuple
    const src_ip = extractSrcIp(&buffer);
    const dst_ip = extractDstIp(&buffer);
    const protocol = extractProtocol(&buffer);

    // Make routing decision
    const decision = router.config.route_cb(
        src_ip, src_port, dst_ip, dst_port, protocol,
    );

    switch (decision) {
        .Direct => forwardToEgress(&buffer),
        .Socks5 => forwardToProxy(&buffer),
        .Drop => {},
        .Local => _ = std.posix.write(config.tun.fd, &buffer),
        .Nat => forwardWithNat(&buffer),
    }

    // Resubmit read
    loop.io(&tun_io, config.tun.fd, .readable, onTunReadable, null);
}
```

## Platform Support

| Platform | TUN | Event Loop | Zero-Copy | Notes |
|----------|-----|------------|-----------|-------|
| Linux | Yes | epoll | Yes | Uses ringbuf mmap |
| macOS | Yes | kqueue | Yes | Uses ringbuf mmap |
| Windows | Yes | IOCP | Yes | Uses VirtualAlloc |
| Android | Yes | epoll | Yes | Same as Linux |
| iOS | Yes | kqueue | Yes | Same as macOS |

## Routing Loop Prevention

When all traffic is routed through TUN (0.0.0.0/0), packets from the router itself would loop:

```
App → TUN → Router → Routing Table → TUN → ... (infinite loop!)
```

**Solution**: Egress traffic uses raw socket with SO_BINDTODEVICE, NOT TUN write():

```zig
fn forwardToEgress(packet: []const u8) !void {
    const sock = try std.posix.socket(
        std.posix.AF_INET,
        std.posix.SOCK_RAW,
        std.posix.IPPROTO_RAW,
    );
    defer std.posix.close(sock);

    // Bind to egress interface
    try std.posix.setsockopt(sock, std.posix.SOL_SOCKET, std.posix.SO_BINDTODEVICE, &egress_iface);

    // Send directly (bypasses TUN)
    _ = try std.posix.send(sock, packet, 0);
}
```

## Performance Characteristics

| Operation | Complexity | Notes |
|-----------|------------|-------|
| Route lookup | O(1) avg | 4-tuple hash table |
| NAT session find | O(1) avg | Open addressing hash |
| TCP connection find | O(1) | Direct 4-tuple lookup |
| Packet forwarding | O(1) | Zero-copy when enabled |

## Default Capacities

| Resource | Default | Max | Use Case |
|----------|---------|-----|----------|
| TCP connections | 4096 | 65536 | Web browsing |
| UDP NAT sessions | 8192 | 65536 | DNS, gaming, VoIP |
| Ring buffer | 4MB | 64MB | Batch packet processing |
| NAT table size | 16384 | 131072 | Hash collision prevention |

## Build Commands

```bash
# Build native library and run unit tests
zig build

# Build and run integration tests
zig build test

# Build all platform static libraries
zig build all

# Cross-compile to specific target
zig build -Dtarget=x86_64-linux-gnu
zig build -Dtarget=aarch64-macos
```

## Usage Example

```zig
// Create router with configuration
var router = try ztun.router.Router.init(.{
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

// Start event loop (blocking)
router.run();
```
