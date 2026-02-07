# ztun Development Todo List

**Version**: 0.1.5
**Last Updated**: 2026-02-08

---

## Release v0.1.5 - Transparent Proxy on macOS

**Goal**: Implement real transparent proxy application on macOS with route filtering

### Features

1. **ICMP Auto-Reply**: Intercept and respond to all ICMP echo requests through TUN
2. **UDP NAT Proxy**: NAT all UDP traffic through egress interface
3. **IP-based Routing**: Route 111.45.11.5 to SOCKS5 proxy (127.0.0.1:1080)

### Architecture

```
tun2sock Application
    |
    +-- RouteCallback (filtering logic)
    |       |
    |       +-- ICMP (protocol=1)  --> Local (auto-reply)
    |       +-- UDP (protocol=17)  --> Nat (NAT all UDP)
    |       +-- TCP to 111.45.11.5 --> Socks5
    |       +-- Private IPs        --> Local (normal routing)
    |
    +-- Router (forwarding engine)
    |       |
    |       +-- TunDevice (utun on macOS)
    |       +-- NAT table (UDP session tracking)
    |       +-- SOCKS5 client (TCP proxy)
    |       +-- ICMP handler (echo reply)
    |
    +-- Egress Interface (en0)
```

---

## Tasks

### Phase 1: Design Route Filtering Interface (DONE)

- [x] **Task 1.1**: Design filtering interfaces in `src/router/route.zig`
  - Add `FilterRule` struct (match conditions + action)
  - Add `FilterChain` struct (ordered list of rules)
  - Add `IpMatcher` enum (exact, CIDR, range)
  - Add helper functions for IP matching
  - Location: `src/router/route.zig`

- [x] **Task 1.2**: Define standard filter actions
  - `Local` - Handle locally (TUN write-back)
  - `Socks5` - Forward through SOCKS5 proxy
  - `Nat` - NAT and forward
  - `Direct` - Direct socket forward
  - `Drop` - Silently drop

### Phase 2: Implement Route Filtering Rules (DONE)

- [x] **Task 2.1**: Implement IP matching utilities
  - `matchExact()` - Exact IP match
  - `matchCidr()` - CIDR range match (e.g., 10.0.0.0/8)
  - `matchPrivate()` - RFC 1918 private ranges
  - Location: `src/router/route.zig`

- [x] **Task 2.2**: Create default filter chain for transparent proxy
  - Rule 1: ICMP echo -> Local (auto-reply)
  - Rule 2: Private IPs -> Local (normal routing)
  - Rule 3: UDP -> Nat (NAT all UDP)
  - Rule 4: 111.45.11.5 TCP -> Socks5
  - Location: `src/router/route.zig`

### Phase 3: Update tun2sock Application (DONE)

- [x] **Task 3.1**: Update routeCallback in `src/tun2sock.zig`
  - Add ICMP protocol handling (protocol=1 -> Local)
  - Change UDP routing: ALL UDP -> Nat (not just target IP)
  - Keep TCP routing: 111.45.11.5 -> Socks5, others -> Local
  - Add detailed comments for each rule

- [x] **Task 3.2**: Configure system route using network.addRoute() API
  - Add `configureTunRoute()` function in `src/tun2sock.zig`
  - Route 111.45.11.5 -> TUN (10.0.0.1) using C-based routing API
  - Do NOT use ifconfig/route shell commands
  - Uses `network.ipv4Route()` and `network.addRoute()` pattern

- [ ] **Task 3.3**: Verify ICMP echo handling
  - Router already has `handleIcmpEcho()` for Local decision
  - Verify TUN write-back works on macOS utun
  - Test with: `ping -I utunX 8.8.8.8`

- [ ] **Task 3.4**: Enhance debug output
  - Log each routing decision with packet info
  - Show rule matching details
  - Add `-d` for verbose output

### Phase 4: Testing on macOS (IN PROGRESS)

- [x] **Task 4.1**: Build for macOS native (x86_64)
  ```bash
  zig build tun2sock -Dtarget=x86_64-macos
  ```

- [ ] **Task 4.2**: Test ICMP auto-reply
  ```bash
  # Start tun2sock
  sudo ./tun2sock --tun-ip 10.0.0.1 --proxy 127.0.0.1:1080 -d

  # In another terminal, test ping through TUN
  ping -I utunX 8.8.8.8

  # Expected: ICMP echo reply received
  ```

- [ ] **Task 4.3**: Test UDP NAT proxy
  ```bash
  # Start DNS query through TUN
  dig @8.8.8.8 example.com

  # Expected: DNS query forwarded via NAT
  # Check: NAT session created in router stats
  ```

- [ ] **Task 4.4**: Test IP routing to SOCKS5
  ```bash
  # Connect to 111.45.11.5 through SOCKS5
  curl --socks5 127.0.0.1:1080 http://111.45.11.5/

  # Expected: Traffic routed through SOCKS5 proxy
  # Check: TCP connection to proxy in logs
  ```

### Phase 5: Performance and Stability

- [ ] **Task 5.1**: Stress test UDP NAT
  - Multiple concurrent UDP flows
  - Verify session cleanup works
  - Monitor memory usage

- [ ] **Task 5.2**: Long-running stability test
  - Run for 1+ hour
  - Monitor for memory leaks
  - Verify no packet drops

---

## Implementation Details

### RouteCallback Signature (unchanged)

```zig
fn routeCallback(
    src_ip: u32,      // Source IP (network byte order)
    src_port: u16,    // Source port (host byte order)
    dst_ip: u32,      // Destination IP (network byte order)
    dst_port: u16,    // Destination port (host byte order)
    protocol: u8,     // IP protocol (6=TCP, 17=UDP, 1=ICMP)
) RouteDecision {
    // Return routing decision
}
```

### Updated Routing Rules

| Protocol | Destination | Action | Description |
|----------|-------------|--------|-------------|
| ICMP (1) | Any | Local | Auto-reply echo request |
| UDP (17) | Any public | Nat | NAT and forward via egress |
| TCP (6) | 111.45.11.5 | Socks5 | Forward to proxy |
| TCP (6) | Private IPs | Local | Normal routing |
| Any | Private IPs | Local | Normal routing |
| Any | Multicast | Drop | Silently drop |

### Key IP Addresses (network byte order)

```zig
const TARGET_IP = 0x6F2D0B05;  // 111.45.11.5 (0x6F=111, 0x2D=45, 0x0B=11, 0x05=5)
const PRIVATE_10 = 0x0A000000;  // 10.0.0.0/8
const PRIVATE_172 = 0xAC100000;  // 172.16.0.0/12
const PRIVATE_192 = 0xC0A80000;  // 192.168.0.0/16
const LOOPBACK = 0x7F000000;    // 127.0.0.0/8
```

### Route Configuration (using C API, NOT shell commands)

```zig
// Use network.addRoute() API instead of shell commands
const route = network.ipv4Route(
    target_ip,      // 111.45.11.5 (network byte order)
    0xFFFFFFFF,    // Netmask: /32 (single host)
    tun_ip,        // Gateway: 10.0.0.1 (TUN IP)
    tun_ifindex,   // Interface index
    100,           // Metric
);
network.deleteRoute(&route) catch {};  // Clean existing
network.addRoute(&route) catch |err| { // Add new route
    std.debug.print("Warning: Route config failed\n", .{});
};
```

**IMPORTANT**: Do NOT use `ifconfig` or `route` shell commands. Use the C-based `network` module API as shown in `tests/test_tun.zig`.

---

## Build Commands

```bash
# Native macOS build (x86_64)
zig build tun2sock -Dtarget=x86_64-macos

# Build and run tests
zig build test

# Build debug binary (default)
zig build tun2sock -Dtarget=x86_64-macos

# Build release binary
zig build tun2sock -Dtarget=x86_64-macos -Doptimize=ReleaseSafe

# Run with debug logging
sudo ./zig-out/bin/macos/tun2sock --tun-ip 10.0.0.1 --proxy 127.0.0.1:1080 -d
```

---

## Testing Checklist

- [ ] ICMP echo request gets reply
- [ ] UDP DNS queries forwarded via NAT
- [ ] TCP to 111.45.11.5 goes through SOCKS5
- [ ] Private IP traffic handled locally
- [ ] Multicast traffic dropped
- [ ] No memory leaks during extended run
- [ ] Router statistics show correct counts

---

## Notes

- macOS TUN (utun) requires 4-byte AF_INET header on packet write
- NAT timeout: 30 seconds (configurable)
- SOCKS5 proxy: 127.0.0.1:1080 (configurable via --proxy)
- TUN IP: 10.0.0.1/24 (configurable via --tun-ip)
