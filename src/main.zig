//! ztun - Cross-platform TUN device library
//!
//! A synchronous, cross-platform TUN device library implemented in pure Zig.
//!
//! # Quick Start
//!
//! ```zig
//! const tun = @import("ztun");
//!
//! // Create a TUN device with options
//! const opts = tun.Options{
//!     .mtu = 1500,
//!     .network = .{
//!         .ipv4 = .{ .address = .{ 10, 0, 0, 1 }, .prefix = 24 },
//!     },
//! };
//!
//! var device = try tun.create(std.heap.c_allocator, opts);
//! defer device.destroy();
//!
//! // Read/write packets
//! var buf: [1500]u8 = undefined;
//! const n = try device.read(&buf);
//! try device.write(buf[0..n]);
//! ```
//!
//! # Supported Platforms
//!
//! - Linux (using /dev/net/tun)
//! - macOS/iOS (using utun sockets)
//! - Windows (using Wintun DLL)
//! - Android (using /dev/net/tun)

const tun = @import("tun");

// Export public API
pub const TunDevice = tun.TunDevice;
pub const TunError = tun.TunError;
pub const Options = tun.Options;
pub const Ipv4Address = tun.Ipv4Address;
pub const Ipv6Address = tun.Ipv6Address;
pub const Device = tun.Device;
pub const DeviceOps = tun.DeviceOps;
