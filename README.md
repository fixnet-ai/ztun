# ztun - Cross-Platform TUN Device Library

A pure Zig library for creating and managing TUN devices on Linux, macOS, and Windows.

## Features

- **Cross-Platform**: Linux (/dev/net/tun), macOS (utun), Windows (Wintun)
- **Pure Zig**: No C dependencies, compiles with Zig 0.13.0
- **Simple API**: Easy-to-use builder pattern for device creation
- **RingBuffer**: Internal batch packet handling optimization

## Quick Start

```zig
const ztun = @import("tun");

// Build a TUN device
var builder = ztun.DeviceBuilder.init();
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

## API Reference

### DeviceBuilder

- `init()` - Create a new builder
- `setName(name: []const u8)` - Set device name (optional, auto-assigned if empty)
- `setMtu(mtu: u16)` - Set MTU (default: 1500)
- `setIpv4(address: Ipv4Address, prefix: u8, peer: ?Ipv4Address)` - Configure IPv4
- `setIpv6(address: Ipv6Address, prefix: u32)` - Configure IPv6 (optional)
- `build() !*DeviceContext` - Create the device

### Device

- `recv(buf: []u8) !usize` - Read a packet from TUN
- `send(buf: []const u8) !usize` - Write a packet to TUN
- `name() ![]const u8` - Get device name
- `mtu() !u16` - Get MTU
- `destroy()` - Destroy device and release resources
