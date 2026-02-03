# ztun - Cross-Platform TUN Device Library

A pure Zig library for creating/managing TUN devices and a pure Zig IP stack (TCP/UDP/ICMP) on Linux, macOS, and Windows.

## Features

- **TUN Device**: Cross-platform TUN support (Linux /dev/net/tun, macOS utun, Windows Wintun)
- **Pure Zig**: No C dependencies, compiles with Zig 0.13.0
- **IP Stack**: Full TCP/UDP/ICMP protocol implementation with static memory allocation
- **Builder Pattern**: Easy device creation and configuration
- **RingBuffer**: Internal batch packet handling optimization
- **Dual Stack**: Complete IPv4 and IPv6 support

## Quick Start

### TUN Device Only

```zig
const tun = @import("tun");

// Build a TUN device
var builder = tun.DeviceBuilder.init();
builder.setName("tun0");
builder.setMtu(1500);
builder.setIpv4(.{ 10, 0, 0, 1 }, 24, null);

const device = builder.build() catch {
    // Handle error
};
defer device.destroy();

// Read/write packets
var buf: [4096]u8 = undefined;
const len = try device.recv(&buf);
try device.send(buf[0..len]);
```

### TUN + IP Stack

```zig
const tun = @import("tun");
const ipstack = @import("ipstack");

// Build a TUN device
var builder = tun.DeviceBuilder.init();
builder.setName("tun0");
const device = try builder.build();
defer device.destroy();

// Initialize IP stack with static memory (no heap allocation)
var stack = ipstack.StaticIpstack.init(.{
    .tun_device = device,
    .local_ip = ip4(10, 0, 0, 1),
    .pseudo_src_ip = ip4(10, 0, 0, 2),
    .callbacks = .{
        .onTcpAccept = myAccept,
        .onTcpData = myData,
        .onUdp = myUdp,
    },
});

// Process packets from TUN
var pkt_buf: [65536]u8 = undefined;
while (true) {
    const len = try device.recv(&pkt_buf);
    try stack.processPacket(pkt_buf[0..len]);
}
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
│   ├── tun/                  # TUN device library
│   │   ├── mod.zig           # Main module (exports, imports)
│   │   ├── builder.zig       # DeviceBuilder
│   │   ├── device.zig        # Device interface
│   │   ├── device_linux.zig  # Linux implementation
│   │   ├── device_macos.zig  # macOS implementation
│   │   ├── device_windows.zig # Windows implementation
│   │   ├── platform.zig      # Platform utilities
│   │   └── ringbuf.zig       # Ring buffer for packet batching
│   │
│   ├── ipstack/              # Pure Zig IP stack
│   │   ├── mod.zig           # Main module (StaticIpstack)
│   │   ├── checksum.zig      # Internet checksum
│   │   ├── ipv4.zig          # IPv4 header parsing/building
│   │   ├── ipv6.zig          # IPv6 header parsing/building
│   │   ├── tcp.zig           # TCP protocol utilities
│   │   ├── udp.zig           # UDP protocol utilities
│   │   ├── icmp.zig          # ICMP protocol utilities
│   │   ├── connection.zig    # TCP connection state machine
│   │   └── callbacks.zig     # Callback interface definitions
│   │
│   └── main.zig              # Root module exports
│
├── tests/
│   ├── test_unit.zig         # Unit tests (Zig test blocks)
│   └── test_runner.zig       # Integration tests (executable)
│
├── docs/
│   └── ztun-design.md        # Architecture documentation
│
├── build.zig                 # Zig build script
└── README.md                 # This file
```

## API Reference

### TUN Module

**DeviceBuilder:**

- `init()` - Create a new builder
- `setName(name: []const u8)` - Set device name (optional)
- `setMtu(mtu: u16)` - Set MTU (default: 1500)
- `setIpv4(address: Ipv4Address, prefix: u8, peer: ?Ipv4Address)` - Configure IPv4
- `setIpv6(address: Ipv6Address, prefix: u32)` - Configure IPv6 (optional)
- `build() !*Device` - Create the device

**Device:**

- `recv(buf: []u8) !usize` - Read a packet from TUN
- `send(buf: []const u8) !usize` - Write a packet to TUN
- `name() ![]const u8` - Get device name
- `mtu() !u16` - Get MTU
- `destroy()` - Destroy device and release resources

### IP Stack Module

**StaticIpstack:**

- `init(config: Config) StaticIpstack` - Initialize with static memory
- `processPacket(packet: []const u8) !void` - Process incoming packet
- `tcpSend(conn: *Connection, data: []const u8) !void` - Send TCP data
- `udpSend(src_ip: u32, src_port: u16, dst_ip: u32, dst_port: u16, data: []const u8) !void` - Send UDP packet
- `cleanupTimeouts(current_time: u32) void` - Clean up idle connections

**Callbacks:**

- `onTcpAccept(src_ip, src_port, dst_ip, dst_port) bool` - Accept/reject TCP connection
- `onTcpData(conn: *Connection, data: []const u8) void` - Receive TCP data
- `onTcpReset(conn: *Connection) void` - Connection reset
- `onTcpClose(conn: *Connection) void` - Connection closed
- `onTcpEstablished(conn: *Connection) void` - Connection established
- `onUdp(src_ip, src_port, dst_ip, dst_port, data) void` - Receive UDP packet
- `onIcmp(src_ip, dst_ip, type, code, data) void` - Receive ICMP packet
- `onIcmpEcho(src_ip, dst_ip, identifier, sequence, payload) bool` - Echo request
