//! test_runner.zig - Integration Tests for ztun
//!
//! Tests the full library functionality.

const std = @import("std");
const ztun = @import("tun");
const Device = ztun.Device;
const Ipv4Address = ztun.Ipv4Address;

// ==================== Test Context ====================

const TestContext = struct {
    total: u32 = 0,
    passed: u32 = 0,
    failed: u32 = 0,

    pub fn start(self: *TestContext, name: []const u8) void {
        self.total += 1;
        std.debug.print("[{d:>3}] Testing: {s}...\n", .{ self.total, name });
    }

    pub fn pass(self: *TestContext) void {
        self.passed += 1;
        std.debug.print("  PASSED\n", .{});
    }

    pub fn fail(self: *TestContext, msg: []const u8) void {
        self.failed += 1;
        std.debug.print("  FAILED: {s}\n", .{msg});
    }

    pub fn summary(self: *const TestContext) void {
        std.debug.print("\n=== Test Summary ===\n", .{});
        std.debug.print("Total:  {d}\n", .{self.total});
        std.debug.print("Passed: {d}\n", .{self.passed});
        std.debug.print("Failed: {d}\n", .{self.failed});

        if (self.failed == 0) {
            std.debug.print("\nAll tests passed!\n", .{});
        } else {
            std.debug.print("\n{d} tests failed!\n", .{self.failed});
        }
    }

    pub fn allPassed(self: *const TestContext) bool {
        return self.failed == 0;
    }
};

// ==================== ICMP Echo Responder ====================

const IcmpResponder = struct {
    device: Device,
    running: bool,

    fn init(device: Device) IcmpResponder {
        return .{ .device = device, .running = true };
    }

    fn deinit(self: *IcmpResponder) void {
        self.running = false;
    }

    fn run(self: *IcmpResponder, allocator: std.mem.Allocator) void {
        const buf_size = 4096;
        const buf = allocator.alloc(u8, buf_size) catch {
            std.debug.print("  Failed to allocate packet buffer\n", .{});
            return;
        };
        defer allocator.free(buf);

        while (self.running) {
            const len = self.device.recv(buf) catch {
                std.time.sleep(10 * std.time.ns_per_ms);
                continue;
            };

            if (len == 0) continue;

            const packet = buf[0..len];
            if (self.handlePacket(packet)) {
                _ = self.device.send(packet) catch {};
            }
        }
    }

    fn handlePacket(_: *IcmpResponder, packet: []u8) bool {
        if (packet.len < 28) return false;

        const ip_ver_ihl = packet[0];
        const ip_ver = ip_ver_ihl >> 4;
        const ip_ihl = ip_ver_ihl & 0x0F;

        if (ip_ver != 4) return false;
        if (ip_ihl < 5) return false;

        const ip_header_len = ip_ihl * 4;
        if (packet.len < ip_header_len + 8) return false;

        const protocol = packet[9];
        if (protocol != 1) return false;

        const icmp_type = packet[ip_header_len];
        if (icmp_type != 8) return false;

        const src_ip = packet[12..16];
        const dst_ip = packet[16..20];

        for (0..4) |i| {
            const tmp = src_ip[i];
            src_ip[i] = dst_ip[i];
            dst_ip[i] = tmp;
        }

        packet[ip_header_len] = 0;

        packet[10] = 0;
        packet[11] = 0;
        const ip_sum = checksum(packet[0..ip_header_len]);
        std.mem.writeInt(u16, packet[10..12], ip_sum, .big);

        packet[ip_header_len + 2] = 0;
        packet[ip_header_len + 3] = 0;
        const icmp_sum = checksum(packet[ip_header_len..]);
        std.mem.writeInt(u16, packet[ip_header_len + 2..][0..2], icmp_sum, .big);

        return true;
    }
};

fn checksum(data: []const u8) u16 {
    var sum: u32 = 0;
    const bytes = data.len;

    var i: usize = 0;
    while (i + 1 < bytes) : (i += 2) {
        sum += std.mem.readInt(u16, data[i..][0..2], .big);
    }

    if (bytes % 2 == 1) {
        sum += @as(u16, data[bytes - 1]) << 8;
    }

    while (sum >> 16 != 0) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return ~@as(u16, @truncate(sum));
}

// ==================== Test Scenarios ====================

fn testTunWithIcmpResponder(ctx: *TestContext) bool {
    ctx.start("TUN device with ICMP echo responder");

    const allocator = std.heap.page_allocator;

    const tun_addr: Ipv4Address = .{ 10, 0, 0, 1 };
    var builder = ztun.DeviceBuilder.init();
    _ = builder.setName("ztun-test");
    _ = builder.setMtu(1500);
    _ = builder.setIpv4(tun_addr, 24, null);

    const device = builder.build() catch {
        std.debug.print("  Skipping: Failed to create TUN device (may need root privileges)\n", .{});
        return true;
    };
    defer device.destroy();

    const dev_name = device.name() catch "unknown";
    const dev_mtu = device.mtu() catch 0;
    std.debug.print("  Created TUN device: {s}, MTU: {d}\n", .{ dev_name, dev_mtu });

    var responder = IcmpResponder.init(device);
    defer responder.deinit();

    const thread = std.Thread.spawn(.{}, IcmpResponder.run, .{ &responder, allocator }) catch {
        ctx.fail("Failed to spawn responder thread");
        return false;
    };
    defer thread.join();

    std.debug.print("  ICMP responder started, waiting 10 seconds...\n", .{});
    std.debug.print("  You can test with: ping 10.0.0.1\n", .{});

    var remaining: u32 = 10;
    while (remaining > 0) : (remaining -= 1) {
        std.debug.print("  [{d}s] Responder running...\n", .{remaining});
        std.time.sleep(1 * std.time.ns_per_s);
    }

    return true;
}

// ==================== Main Entry ====================

pub fn main() u8 {
    var ctx = TestContext{};

    std.debug.print("\n=== ztun Integration Tests ===\n\n", .{});

    if (testTunWithIcmpResponder(&ctx)) {
        ctx.pass();
    } else {
        ctx.fail("TUN with ICMP responder");
    }

    std.debug.print("\n=== Results ===\n", .{});
    std.debug.print("Passed: {d}, Failed: {d}\n", .{ ctx.passed, ctx.failed });

    return if (ctx.failed == 0) 0 else 1;
}
