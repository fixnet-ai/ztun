//! test_unit.zig - Unit Tests for ztun
//!
//! Tests individual functions with no external dependencies.
//! RingBuffer tests are included here since they have internal tests.

const std = @import("std");
const tun = @import("tun");
const ipstack = @import("ipstack");
const DeviceConfig = tun.DeviceConfig;
const Ipv4Address = tun.Ipv4Address;
const Ipv6Address = tun.Ipv6Address;
const NetworkAddress = tun.NetworkAddress;
const DeviceContext = tun.DeviceContext;

// ==================== IPv4 Address Tests ====================

test "Ipv4Address: create from bytes" {
    const addr: Ipv4Address = .{ 10, 0, 0, 1 };
    try std.testing.expectEqual(@as(u8, 10), addr[0]);
    try std.testing.expectEqual(@as(u8, 0), addr[1]);
    try std.testing.expectEqual(@as(u8, 0), addr[2]);
    try std.testing.expectEqual(@as(u8, 1), addr[3]);
}

test "Ipv4Address: common networks" {
    // Localhost
    const localhost: Ipv4Address = .{ 127, 0, 0, 1 };
    try std.testing.expectEqual(@as(u8, 127), localhost[0]);

    // Private network 10.0.0.0/8
    const private10: Ipv4Address = .{ 10, 0, 0, 1 };
    try std.testing.expectEqual(@as(u8, 10), private10[0]);

    // Private network 192.168.0.0/16
    const private192: Ipv4Address = .{ 192, 168, 1, 100 };
    try std.testing.expectEqual(@as(u8, 192), private192[0]);
    try std.testing.expectEqual(@as(u8, 168), private192[1]);
}

// ==================== IPv6 Address Tests ====================

test "Ipv6Address: create from bytes" {
    const addr: Ipv6Address = .{ 0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    try std.testing.expectEqual(@as(u8, 0xfd), addr[0]);
    try std.testing.expectEqual(@as(u8, 1), addr[15]);
}

test "Ipv6Address: localhost" {
    const localhost: Ipv6Address = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    try std.testing.expectEqual(@as(u8, 1), localhost[15]);
}

test "Ipv6Address: link-local" {
    const linklocal: Ipv6Address = .{ 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    try std.testing.expectEqual(@as(u8, 0xfe), linklocal[0]);
    try std.testing.expectEqual(@as(u8, 0x80), linklocal[1]);
}

// ==================== NetworkAddress Tests ====================

test "NetworkAddress: create with destination" {
    const addr: Ipv4Address = .{ 10, 0, 0, 1 };
    const dest: Ipv4Address = .{ 10, 0, 0, 254 };
    const network = NetworkAddress{
        .address = addr,
        .prefix = 24,
        .destination = dest,
    };
    try std.testing.expectEqual(addr, network.address);
    try std.testing.expectEqual(@as(u8, 24), network.prefix);
    try std.testing.expect(std.mem.eql(u8, &dest, &network.destination.?));
}

test "NetworkAddress: create without destination" {
    const addr: Ipv4Address = .{ 192, 168, 1, 1 };
    const network = NetworkAddress{
        .address = addr,
        .prefix = 24,
        .destination = null,
    };
    try std.testing.expectEqual(addr, network.address);
    try std.testing.expect(network.destination == null);
}

// ==================== DeviceBuilder Tests ====================

test "DeviceBuilder: init returns empty builder" {
    const builder = tun.DeviceBuilder.init();
    try std.testing.expect(builder.mtu == null);
    try std.testing.expect(builder.ipv4_addr == null);
    try std.testing.expect(builder.ipv6_addr == null);
}

test "DeviceBuilder: setMtu" {
    var builder = tun.DeviceBuilder.init();
    _ = builder.setMtu(1500);
    try std.testing.expectEqual(@as(u16, 1500), builder.mtu.?);
    _ = builder.setMtu(9000);
    try std.testing.expectEqual(@as(u16, 9000), builder.mtu.?);
}

test "DeviceBuilder: setIpv4" {
    var builder = tun.DeviceBuilder.init();
    const addr: Ipv4Address = .{ 10, 0, 0, 1 };
    _ = builder.setIpv4(addr, 24, null);
    try std.testing.expectEqual(addr, builder.ipv4_addr.?);
    try std.testing.expectEqual(@as(u8, 24), builder.ipv4_prefix.?);
    try std.testing.expect(builder.ipv4_destination == null);
}

test "DeviceBuilder: setIpv4 with destination" {
    var builder = tun.DeviceBuilder.init();
    const addr: Ipv4Address = .{ 10, 0, 0, 1 };
    const dest: Ipv4Address = .{ 10, 0, 0, 254 };
    _ = builder.setIpv4(addr, 24, dest);
    try std.testing.expect(builder.ipv4_destination != null);
    try std.testing.expectEqual(dest, builder.ipv4_destination.?);
}

test "DeviceBuilder: setIpv6" {
    var builder = tun.DeviceBuilder.init();
    const addr: Ipv6Address = .{ 0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    _ = builder.setIpv6(addr, 64);
    try std.testing.expectEqual(addr, builder.ipv6_addr.?);
    try std.testing.expectEqual(@as(u8, 64), builder.ipv6_prefix.?);
}

test "DeviceBuilder: fluent interface" {
    var builder = tun.DeviceBuilder.init();
    const addr4: Ipv4Address = .{ 10, 0, 0, 1 };
    const addr6: Ipv6Address = .{ 0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };

    _ = builder.setMtu(1500)
        .setIpv4(addr4, 24, null)
        .setIpv6(addr6, 64);

    try std.testing.expectEqual(@as(u16, 1500), builder.mtu.?);
}

// ==================== DeviceConfig Tests ====================

test "DeviceConfig: default values" {
    const config = DeviceConfig{};
    try std.testing.expect(config.mtu == null);
    try std.testing.expect(config.ipv4 == null);
    try std.testing.expect(config.ipv6 == null);
    try std.testing.expect(config.ipv6_prefix == null);
}

test "DeviceConfig: full configuration" {
    const addr: Ipv4Address = .{ 10, 0, 0, 1 };
    const dest: Ipv4Address = .{ 10, 0, 0, 254 };
    const ipv6_addr: Ipv6Address = .{ 0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };

    const config = DeviceConfig{
        .mtu = 1500,
        .ipv4 = .{
            .address = addr,
            .prefix = 24,
            .destination = dest,
        },
        .ipv6 = ipv6_addr,
        .ipv6_prefix = 64,
    };

    try std.testing.expectEqual(@as(u16, 1500), config.mtu.?);
    try std.testing.expectEqual(addr, config.ipv4.?.address);
    try std.testing.expectEqual(@as(u8, 24), config.ipv4.?.prefix);
    try std.testing.expectEqual(dest, config.ipv4.?.destination.?);
}

// ==================== TunError Tests ====================

test "TunError: error types exist" {
    // Verify all error types are defined
    const errors = &.{
        tun.TunError.InvalidArgument,
        tun.TunError.IoError,
        tun.TunError.NotFound,
        tun.TunError.PermissionDenied,
        tun.TunError.Unknown,
    };
    try std.testing.expect(errors.len == 5);
}

test "TunError: error set conversion" {
    // Test that our error set is compatible with standard errors
    const test_fn = (struct {
        fn inner() tun.TunError!void {
            return error.IoError;
        }
    }).inner;

    const result = test_fn();
    try std.testing.expect(result == error.IoError);
}

// ==================== RingBuffer Tests ====================

test "RingBuffer: init and deinit" {
    const capacity = 4096;
    var rb = try tun.RingBuffer.init(capacity);
    defer rb.deinit();

    try std.testing.expectEqual(capacity, rb.capacity);
    try std.testing.expect(rb.capacity > 0);
}

test "RingBuffer: write and read" {
    const capacity = 4096;
    var rb = try tun.RingBuffer.init(capacity);
    defer rb.deinit();

    const test_data = "Hello, Ring Buffer!";
    rb.write(0, test_data);

    var read_buf: [100]u8 = undefined;
    rb.read(0, read_buf[0..test_data.len]);
    try std.testing.expectEqualStrings(test_data, read_buf[0..test_data.len]);
}

test "RingBuffer: wrap-around write" {
    const page_size = std.mem.page_size;
    var rb = try tun.RingBuffer.init(page_size * 4);
    defer rb.deinit();

    const test_data = "Wrap-around test data";
    rb.write(rb.capacity - 10, test_data);

    var read_buf: [100]u8 = undefined;
    rb.read(rb.capacity - 10, read_buf[0..test_data.len]);
    try std.testing.expectEqualStrings(test_data, read_buf[0..test_data.len]);
}

test "RingBuffer: wrap-around read" {
    const page_size = std.mem.page_size;
    var rb = try tun.RingBuffer.init(page_size * 4);
    defer rb.deinit();

    var test_data: [100]u8 = undefined;
    @memset(&test_data, 'X');
    rb.write(rb.capacity - 50, &test_data);

    var read_buf: [100]u8 = undefined;
    rb.read(rb.capacity - 50, read_buf[0..test_data.len]);

    // Verify all 'X' characters
    for (read_buf[0..test_data.len]) |c| {
        try std.testing.expectEqual(@as(u8, 'X'), c);
    }
}

test "RingBuffer: getWriteSlices single" {
    var rb = try tun.RingBuffer.init(4096);
    defer rb.deinit();

    const slices = rb.getWriteSlices(0, 100);
    try std.testing.expectEqual(@as(usize, 1), slices.len);
    try std.testing.expectEqual(@as(usize, 100), slices.slices[0].len);
}

test "RingBuffer: getWriteSlices double" {
    var rb = try tun.RingBuffer.init(4096);
    defer rb.deinit();

    const slices = rb.getWriteSlices(4090, 100);
    try std.testing.expectEqual(@as(usize, 2), slices.len);
    try std.testing.expectEqual(@as(usize, 6), slices.slices[0].len);
    try std.testing.expectEqual(@as(usize, 94), slices.slices[1].len);
}

test "RingBuffer: availableBeforeWrap" {
    var rb = try tun.RingBuffer.init(4096);
    defer rb.deinit();

    try std.testing.expectEqual(@as(usize, 4096), rb.availableBeforeWrap(0));
    try std.testing.expectEqual(@as(usize, 100), rb.availableBeforeWrap(3996));
    try std.testing.expectEqual(@as(usize, 1), rb.availableBeforeWrap(4095));
}

test "RingBuffer: empty buffer read" {
    const capacity = 4096;
    var rb = try tun.RingBuffer.init(capacity);
    defer rb.deinit();

    var buf: [100]u8 = undefined;
    rb.read(0, &buf);
    // Should not panic, just read zeros/undefined
}

// ==================== IP Stack Tests ====================

test "ipstack: module exports" {
    // Verify all expected exports exist
    _ = ipstack.checksum;
    _ = ipstack.ipv4;
    _ = ipstack.ipv6;
    _ = ipstack.tcp;
    _ = ipstack.udp;
    _ = ipstack.icmp;
    _ = ipstack.connection;
    _ = ipstack.callbacks;
}

test "ipstack.callbacks: Callbacks struct" {
    const callbacks = ipstack.callbacks.Callbacks{};
    try std.testing.expect(callbacks.onTcpAccept == null);
    try std.testing.expect(callbacks.onTcpData == null);
    try std.testing.expect(callbacks.onUdp == null);
    try std.testing.expect(callbacks.onIcmpEcho == null);
}

test "ipstack.callbacks: invokeTcpAccept default" {
    const callbacks = ipstack.callbacks.Callbacks{};
    const result = ipstack.callbacks.invokeTcpAccept(&callbacks, 0, 0, 0, 0);
    try std.testing.expect(result == true); // Default: accept all
}

test "ipstack.callbacks: invokeIcmpEcho default" {
    const callbacks = ipstack.callbacks.Callbacks{};
    const result = ipstack.callbacks.invokeIcmpEcho(&callbacks, 0, 0, 0, 0, &.{});
    try std.testing.expect(result == true); // Default: respond to echo
}

test "ipstack.connection: Connection init" {
    var conn: ipstack.connection.Connection = undefined;
    ipstack.connection.initListen(&conn, 0xC0A80101, 80, 0xC0A80102, 12345);

    try std.testing.expectEqual(@as(u32, 0xC0A80101), conn.src_ip);
    try std.testing.expectEqual(@as(u16, 80), conn.src_port);
    try std.testing.expectEqual(@as(u32, 0xC0A80102), conn.dst_ip);
    try std.testing.expectEqual(@as(u16, 12345), conn.dst_port);
    try std.testing.expectEqual(ipstack.connection.State.Listen, conn.state);
}

test "ipstack.connection: keyMatch" {
    var conn: ipstack.connection.Connection = undefined;
    ipstack.connection.initListen(&conn, 0xC0A80101, 80, 0xC0A80102, 12345);

    const key = &ipstack.connection.ConnKey{
        .src_ip = 0xC0A80101,
        .src_port = 80,
        .dst_ip = 0xC0A80102,
        .dst_port = 12345,
    };

    try std.testing.expect(ipstack.connection.keyMatch(&conn, key));
}

test "ipstack.connection: reverseKey" {
    const key = &ipstack.connection.ConnKey{
        .src_ip = 0xC0A80101,
        .src_port = 80,
        .dst_ip = 0xC0A80102,
        .dst_port = 12345,
    };

    const rev = ipstack.connection.reverseKey(key);
    try std.testing.expectEqual(@as(u32, 0xC0A80102), rev.src_ip);
    try std.testing.expectEqual(@as(u16, 12345), rev.src_port);
    try std.testing.expectEqual(@as(u32, 0xC0A80101), rev.dst_ip);
    try std.testing.expectEqual(@as(u16, 80), rev.dst_port);
}

test "ipstack.connection: hasTimedOut" {
    var conn: ipstack.connection.Connection = undefined;
    ipstack.connection.initListen(&conn, 0, 0, 0, 0);
    conn.last_activity = 100;

    // Not timed out (current time = 150, timeout = 300)
    try std.testing.expect(!ipstack.connection.hasTimedOut(&conn, 150, 300));

    // Timed out (current time = 500, last_activity = 100, timeout = 300)
    try std.testing.expect(ipstack.connection.hasTimedOut(&conn, 500, 300));
}

test "ipstack.checksum: basic" {
    const data = [_]u8{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
    const sum = ipstack.checksum.checksum(&data, data.len);
    // Checksum should not be zero for non-zero data
    try std.testing.expect(sum != 0);
}

test "ipstack.checksum: zero data" {
    const data = [_]u8{0} ** 10;
    const sum = ipstack.checksum.checksum(&data, data.len);
    // All zeros should produce 0xFFFF (which is ~0)
    try std.testing.expectEqual(@as(u16, 0xFFFF), sum);
}

test "ipstack.checksum: odd length" {
    const data = [_]u8{ 0x01, 0x02, 0x03 };
    const sum = ipstack.checksum.checksum(&data, data.len);
    try std.testing.expect(sum != 0);
}

test "ipstack.ipv4: constants" {
    try std.testing.expectEqual(@as(u8, 1), ipstack.ipv4.PROTO_ICMP);
    try std.testing.expectEqual(@as(u8, 6), ipstack.ipv4.PROTO_TCP);
    try std.testing.expectEqual(@as(u8, 17), ipstack.ipv4.PROTO_UDP);
    try std.testing.expectEqual(@as(u5, 20), ipstack.ipv4.HDR_MIN_SIZE);
}

test "ipstack.ipv4: header size calculation" {
    // IHL = 5 means 20 bytes (no options)
    const ihl: u8 = 5;
    const header_len = @as(usize, ihl) * 4;
    try std.testing.expectEqual(@as(usize, 20), header_len);
}

test "ipstack.ipv6: constants" {
    try std.testing.expectEqual(@as(usize, 40), ipstack.ipv6.HDR_SIZE);
    try std.testing.expectEqual(@as(u8, 0), ipstack.ipv6.NH_HOP_OPTS);
    try std.testing.expectEqual(@as(u8, 44), ipstack.ipv6.NH_FRAGMENT);
}

test "ipstack.tcp: constants" {
    try std.testing.expectEqual(@as(u5, 20), ipstack.tcp.HDR_MIN_SIZE);
    try std.testing.expectEqual(@as(u8, 0x01), ipstack.tcp.FLAG_FIN);
    try std.testing.expectEqual(@as(u8, 0x02), ipstack.tcp.FLAG_SYN);
}

test "ipstack.udp: constants" {
    try std.testing.expectEqual(@as(u5, 8), ipstack.udp.HDR_SIZE);
}

// ==================== StaticIpstack Tests ====================

test "StaticIpstack: init and reset" {
    var ipstack_ctx: ipstack.StaticIpstack = undefined;

    ipstack.init(&ipstack_ctx, .{
        .local_ip = 0xC0A80101,
        .pseudo_src_ip = 0xC0A80102,
        .callbacks = .{},
        .idle_timeout = 300,
    });

    try std.testing.expectEqual(@as(u32, 0), ipstack_ctx.stats.tcp_connections);
    try std.testing.expect(ipstack_ctx.isn_counter != 0);

    ipstack.reset(&ipstack_ctx);
    try std.testing.expectEqual(@as(u32, 0), ipstack_ctx.stats.tcp_connections);
}

test "StaticIpstack: statistics" {
    var ipstack_ctx: ipstack.StaticIpstack = undefined;

    ipstack.init(&ipstack_ctx, .{
        .local_ip = 0xC0A80101,
        .pseudo_src_ip = 0xC0A80102,
        .callbacks = .{},
    });

    // Manually increment some stats
    ipstack_ctx.stats.udp_packets = 10;
    ipstack_ctx.stats.icmp_packets = 5;
    ipstack_ctx.stats.dropped_packets = 2;

    try std.testing.expectEqual(@as(u32, 10), ipstack_ctx.stats.udp_packets);
    try std.testing.expectEqual(@as(u32, 5), ipstack_ctx.stats.icmp_packets);
    try std.testing.expectEqual(@as(u32, 2), ipstack_ctx.stats.dropped_packets);

    ipstack.reset(&ipstack_ctx);
}

test "StaticIpstack: updateTimestamp" {
    var ipstack_ctx: ipstack.StaticIpstack = undefined;

    ipstack.init(&ipstack_ctx, .{
        .local_ip = 0xC0A80101,
        .pseudo_src_ip = 0xC0A80102,
        .callbacks = .{},
    });

    try std.testing.expectEqual(@as(u32, 0), ipstack_ctx.current_time);

    ipstack.updateTimestamp(&ipstack_ctx, 12345);
    try std.testing.expectEqual(@as(u32, 12345), ipstack_ctx.current_time);
}

test "StaticIpstack: cleanupTimeouts" {
    var ipstack_ctx: ipstack.StaticIpstack = undefined;

    ipstack.init(&ipstack_ctx, .{
        .local_ip = 0xC0A80101,
        .pseudo_src_ip = 0xC0A80102,
        .callbacks = .{},
        .idle_timeout = 10,
    });

    // Add a connection
    var conn: ipstack.connection.Connection = undefined;
    ipstack.connection.initListen(&conn, 0xC0A80101, 12345, 0xC0A80102, 80);
    ipstack_ctx.connections[0] = conn;
    ipstack_ctx.conn_used[0] = true;

    // Set old timestamp
    ipstack.updateTimestamp(&ipstack_ctx, 100);
    ipstack_ctx.connections[0].last_activity = 50;

    // Cleanup
    ipstack.cleanupTimeouts(&ipstack_ctx);

    try std.testing.expect(!ipstack_ctx.conn_used[0]);
    try std.testing.expectEqual(@as(u32, 1), ipstack_ctx.stats.connection_timeouts);
}

test "StaticIpstack: cleanupTimeouts skips fresh connections" {
    var ipstack_ctx: ipstack.StaticIpstack = undefined;

    ipstack.init(&ipstack_ctx, .{
        .local_ip = 0xC0A80101,
        .pseudo_src_ip = 0xC0A80102,
        .callbacks = .{},
        .idle_timeout = 300,
    });

    // Add a connection
    var conn: ipstack.connection.Connection = undefined;
    ipstack.connection.initListen(&conn, 0xC0A80101, 12345, 0xC0A80102, 80);
    ipstack_ctx.connections[0] = conn;
    ipstack_ctx.conn_used[0] = true;

    // Set recent timestamp
    ipstack.updateTimestamp(&ipstack_ctx, 100);
    ipstack_ctx.connections[0].last_activity = 99;

    // Cleanup
    ipstack.cleanupTimeouts(&ipstack_ctx);

    try std.testing.expect(ipstack_ctx.conn_used[0]); // Should still be used
    try std.testing.expectEqual(@as(u32, 0), ipstack_ctx.stats.connection_timeouts);
}
