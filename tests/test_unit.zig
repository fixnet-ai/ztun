//! test_unit.zig - Unit Tests for ztun
//!
//! Tests individual functions with no external dependencies.

const std = @import("std");
const ztun = @import("tun");
const DeviceConfig = ztun.DeviceConfig;
const Ipv4Address = ztun.Ipv4Address;
const Ipv6Address = ztun.Ipv6Address;

// ==================== IPv4 Address Tests ====================

test "Ipv4Address: create from bytes" {
    const addr: Ipv4Address = .{ 10, 0, 0, 1 };
    try std.testing.expectEqual(@as(u8, 10), addr[0]);
    try std.testing.expectEqual(@as(u8, 0), addr[1]);
    try std.testing.expectEqual(@as(u8, 0), addr[2]);
    try std.testing.expectEqual(@as(u8, 1), addr[3]);
}

// ==================== DeviceBuilder Tests ====================

test "DeviceBuilder: init returns empty builder" {
    const builder = ztun.DeviceBuilder.init();
    try std.testing.expect(builder.name == null);
    try std.testing.expect(builder.mtu == null);
    try std.testing.expect(builder.ipv4_addr == null);
}

test "DeviceBuilder: setName" {
    var builder = ztun.DeviceBuilder.init();
    _ = builder.setName("tun0");
    try std.testing.expectEqual(@as([]const u8, "tun0"), builder.name);
}

test "DeviceBuilder: setMtu" {
    var builder = ztun.DeviceBuilder.init();
    _ = builder.setMtu(1500);
    try std.testing.expectEqual(@as(u16, 1500), builder.mtu.?);
}

test "DeviceBuilder: setIpv4" {
    var builder = ztun.DeviceBuilder.init();
    const addr: Ipv4Address = .{ 10, 0, 0, 1 };
    _ = builder.setIpv4(addr, 24, null);
    try std.testing.expectEqual(addr, builder.ipv4_addr.?);
    try std.testing.expectEqual(@as(u8, 24), builder.ipv4_prefix.?);
    try std.testing.expect(builder.ipv4_destination == null);
}

test "DeviceBuilder: setIpv6" {
    var builder = ztun.DeviceBuilder.init();
    const addr: Ipv6Address = .{ 0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    _ = builder.setIpv6(addr, 64);
    try std.testing.expectEqual(addr, builder.ipv6_addr.?);
    try std.testing.expectEqual(@as(u8, 64), builder.ipv6_prefix.?);
}

// ==================== DeviceConfig Tests ====================

test "DeviceConfig: default values" {
    const config = DeviceConfig{};
    try std.testing.expect(config.name == null);
    try std.testing.expect(config.mtu == null);
    try std.testing.expect(config.ipv4 == null);
}

// ==================== TunError Tests ====================

test "TunError: error types exist" {
    // Just verify the error types are defined by checking their names
    const errors = &.{ ztun.TunError.InvalidArgument, ztun.TunError.IoError,
                        ztun.TunError.NotFound, ztun.TunError.PermissionDenied };
    try std.testing.expect(errors.len == 4);
}
