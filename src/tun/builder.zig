//! builder.zig - Device builder for TUN interfaces
//!
//! Provides a builder pattern for configuring and creating TUN devices.

const std = @import("std");
const Device = @import("device.zig").Device;
const DeviceConfig = @import("device.zig").DeviceConfig;
const Ipv4Address = @import("device.zig").Ipv4Address;
const Ipv6Address = @import("device.zig").Ipv6Address;
const TunError = @import("device.zig").TunError;

/// Builder for creating TUN devices
///
/// # Example
/// ```zig
/// var builder = DeviceBuilder.init();
/// builder.setName("tun0");
/// builder.setMtu(1500);
/// builder.setIpv4(.{10, 0, 0, 1}, 24, null);
/// const device = try builder.build();
/// defer device.destroy();
/// ```
pub const DeviceBuilder = struct {
    name: ?[]const u8 = null,
    mtu: ?u16 = null,
    ipv4_addr: ?Ipv4Address = null,
    ipv4_prefix: ?u8 = null,
    ipv4_destination: ?Ipv4Address = null,
    ipv6_addr: ?Ipv6Address = null,
    ipv6_prefix: ?u8 = null,

    /// Initialize a new DeviceBuilder
    pub fn init() DeviceBuilder {
        return .{};
    }

    /// Set the device name
    pub fn setName(self: *DeviceBuilder, name: []const u8) *DeviceBuilder {
        self.name = name;
        return self;
    }

    /// Set the MTU (Maximum Transmission Unit)
    pub fn setMtu(self: *DeviceBuilder, mtu: u16) *DeviceBuilder {
        self.mtu = mtu;
        return self;
    }

    /// Set the IPv4 address and prefix
    ///
    /// - address: IPv4 address bytes
    /// - prefix: CIDR prefix (0-32)
    /// - destination: Optional point-to-point destination address
    pub fn setIpv4(
        self: *DeviceBuilder,
        address: Ipv4Address,
        prefix: u8,
        destination: ?Ipv4Address,
    ) *DeviceBuilder {
        self.ipv4_addr = address;
        self.ipv4_prefix = prefix;
        self.ipv4_destination = destination;
        return self;
    }

    /// Set the IPv6 address and prefix
    ///
    /// - address: IPv6 address bytes
    /// - prefix: CIDR prefix (0-128)
    pub fn setIpv6(self: *DeviceBuilder, address: Ipv6Address, prefix: u8) *DeviceBuilder {
        self.ipv6_addr = address;
        self.ipv6_prefix = prefix;
        return self;
    }

    /// Build the TUN device
    ///
    /// Returns a Device handle on success.
    pub fn build(self: *DeviceBuilder) TunError!Device {
        const config = DeviceConfig{
            .name = self.name,
            .mtu = self.mtu,
            .ipv4 = if (self.ipv4_addr) |addr| .{
                .address = addr,
                .prefix = self.ipv4_prefix orelse 24,
                .destination = self.ipv4_destination,
            } else null,
            .ipv6 = self.ipv6_addr,
            .ipv6_prefix = self.ipv6_prefix,
        };

        return Device.create(config);
    }
};
