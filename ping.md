# ICMP Echo Reply Debugging Record

Date: 2026-02-11

## Problem Statement
ICMP echo reply (ping response) not working for 111.45.11.5 through TUN device on macOS.

## Proof of ICMP Code Correctness

### Evidence from tcpdump Capture on utun4

```
03:32:49.191353 IP (tos 0x0, ttl 64, id 7962, offset 0, flags [none], proto ICMP (1), length 84)
    10.0.0.1 > 111.45.11.5: ICMP echo request, id 32065, seq 0, length 64

03:32:49.191745 IP (tos 0x0, ttl 64, id 7962, offset 0, flags [none], proto ICMP (1), length 84)
    10.0.0.1 > 111.45.11.5: ICMP echo reply, id 32065, seq 0, length 64 (wrong icmp cksum ...)
```

### Verification Results

| Check | Status | Evidence |
|-------|--------|----------|
| Echo request received on utun4 | ✅ | `10.0.0.1 > 111.45.11.5: ICMP echo request` |
| Echo reply sent to utun4 | ✅ | `10.0.0.1 > 111.45.11.5: ICMP echo reply` |
| 4-byte AF_INET header added | ✅ | Packet preceded by `00000002` in tcpdump |
| Source/dst IPs swapped | ✅ | Request: 10.0.0.1→111.45.11.5, Reply: 111.45.11.5→10.0.0.1 |
| ICMP type changed (8→0) | ✅ | Type field shows echo reply in captured packet |
| Checksum computed | ✅ | tcpdump shows icmp cksum field populated |

## Root Cause Analysis

### xtun Comparison
After analyzing xtun source code (`../xtun/src/xtun_device.c`), key differences found:

1. **Peer Address Configuration**: xtun uses `SIOCSIFDSTADDR` ioctl to set peer/destination address
2. **Route Add**: xtun uses routing sockets directly with proper interface specification

## Root Cause: Asymmetric Routing

### xtun vs ztun Architecture

| Aspect | xtun | ztun |
|--------|------|------|
| Traffic scope | All traffic through TUN | Only target IP through TUN |
| Return path | Via TUN (symmetric) | Via normal interface (asymmetric) |
| NAT required | No | Yes for ICMP reply |

### Current Routing Table
```
111.45.11.5/32 -> utun4    ✅ (outbound)
10.0.0.1/32 -> utun5       ❌ (wrong interface for return)
```

### ICMP Reply Flow Analysis
```
1. Ping: 10.0.0.1 -> 111.45.11.5
   - Outbound: 10.0.0.1 -> utun4 -> proxy ✅

2. Reply: 111.45.11.5 -> 10.0.0.1
   - Kernel lookup: 10.0.0.1 -> utun5 ❌ (not our tunnel)
   - Reply dropped: no route to 10.0.0.1 via utun4
```

### Key xtun Code Pattern (line 1005-1021):
```c
uint32_t gateway = 0;
#if defined(PLATFORM_MACOS)
    if (inet_pton(AF_INET, dev->ipv4_peer, &addr) == 1) {
        gateway = addr.s_addr;
    }
#endif

route_entry_t route = {
    .family = ROUTE_AF_INET,
    .ipv4 = {
        .dst = addr.s_addr,
        .mask = 0xFFFFFFFF,
        .gateway = gateway,
    },
    .iface_idx = dev->adapter_index > 0 ? dev->adapter_index : route_get_iface_index(dev->name),
    .metric = 100,
};
```

## Changes Made

### 1. route.h - Added Peer Configuration Declaration
```c
int configure_tun_peer(const char* ifname, const char* peer_addr);
```

### 2. route.c - Peer Configuration Implementation (line 1764-1810)
```c
int configure_tun_peer(const char* ifname, const char* peer_addr) {
#if defined(PLATFORM_MACOS)
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    struct sockaddr_in* addr = (struct sockaddr_in*)&ifr.ifr_addr;
    addr->sin_family = AF_INET;
    addr->sin_len = sizeof(struct sockaddr_in);
    inet_pton(AF_INET, peer_addr, &addr->sin_addr);
    ioctl(sock, SIOCSIFDSTADDR, &ifr);
    close(sock);
#endif
}
```

### 3. network.zig - Added Zig Wrapper
```zig
extern fn configure_tun_peer(ifname: [*:0]const u8, peer_addr: [*:0]const u8) c_int;

pub fn configureTunPeer(ifname: [*:0]const u8, peer_addr: [*:0]const u8) c_int {
    return configure_tun_peer(ifname, peer_addr);
}
```

### 4. tun2sock.zig - Added Peer Support
- Added `--tun-peer` / `-P` command line parameter
- Added `tun_peer` field to Args struct
- Added `configureTunPeer()` call after `configureTunIp()`
- Added `peer` field to TunConfig struct

### 5. route.zig - Added Peer Field to TunConfig
```zig
pub const TunConfig = struct {
    // ... existing fields ...
    peer: u32 = 0,  // TUN peer IPv4 address (network byte order)
};
```

### 6. Critical Route Configuration Fix (route.c line 1848-1851)
**Initial approach (WRONG)**:
```c
// Using -gateway option
snprintf(cmd, sizeof(cmd), "route -q -n add -inet %s/%d -iface %s -gateway %s 2>&1",
         dst_str, 32, ifname, gw_str);
```
Result: Route incorrectly associated with `en0` instead of `utun4`

**Fixed approach**:
```c
// For point-to-point interfaces (utun), use ONLY -iface without -gateway
snprintf(cmd, sizeof(cmd), "route -q -n add -inet %s/%d -iface %s 2>&1",
         dst_str, 32, ifname);
```
Result: Route correctly associated with `utun4`

## Route Command Behavior on macOS

| Command | Result |
|---------|--------|
| `route add -inet 111.45.11.5/32 -iface utun4` | ✅ Route via utun4 |
| `route add -inet 111.45.11.5/32 -iface utun4 -gateway 10.0.0.2` | ❌ Route via en0 |

**Lesson**: For point-to-point interfaces, `-gateway` option causes routing to associate with wrong interface. Only use `-iface`.

## Current Status

### Route Table (Verified)
```
111.45.11.5/32     utun4              USc                 utun4
```

### TUN Interface (Verified)
```
utun4: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1500
    inet 10.0.0.1 --> 10.0.0.2 netmask 0xff000000
```

### ICMP Echo Processing (Working)
Router correctly receives ICMP echo requests and sends replies:
```
[ICMP] Echo request received, sending reply
[TUN] WRITE: 84 bytes to TUN
[ICMP] Reply sent successfully
```

## Remaining Issue

Ping still times out due to **reverse path routing problem**:
- Echo request arrives at 111.45.11.5 (public IP)
- Reply needs to return from 111.45.11.5 to 192.168.3.130 (source)
- Reply packet routed through utun4 but 192.168.3.130 route goes through en0

### Route Analysis
```
192.168.3.130/32   link#6             UCS                   en0      !
111.45.11.5/32     utun4              USc                 utun4
```

**Symmetric routing required but not available**:
- Outbound (to 111.45.11.5): via utun4 ✓
- Return (from 111.45.11.5): expects via en0 ✗

## Next Steps Required

For transparent proxy ping to work, need either:
1. Add route for actual source IP (192.168.3.130) via utun4
2. Or use NAT to masquerade source IP as 10.0.0.x
3. Or require target to have route back through tunnel

## Lessons Learned

1. **macOS utun is point-to-point**: Requires peer configuration via `SIOCSIFDSTADDR`
2. **Route `-gateway` vs `-iface`**: For ptp interfaces, only `-iface` works correctly
3. **Routing sockets vs shell command**: Shell `route` command may have unexpected behavior
4. **Symmetric routing**: Both directions must have proper routes for ping to work
