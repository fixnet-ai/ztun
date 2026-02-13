//! tun2socks.zig - Transparent Proxy TUN to SOCKS5 Forwarding Application
//!
//! A clean implementation demonstrating the use of ztun.router module to forward
//! VPN traffic through a SOCKS5 proxy or directly.
//!
//! Usage: sudo ./tun2socks --tun-ip 10.0.0.1 --proxy 127.0.0.1:1080
//!
//! Architecture:
//!   Application Layer (this file)
//!   - Creates TUN device with provided name and IP
//!   - Implements route callback for routing decisions
//!   - Uses network.zig for route configuration
//!
//!   Router Layer (ztun.router)
//!   - libxev event loop for async I/O
//!   - TUN async read
//!   - TCP connection pool
//!   - UDP NAT table
//!   - Proxy forwarder (SOCKS5 backend)

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const tun = @import("tun");
const router = @import("router");
const network = @import("network");
const ipstack = @import("ipstack");

// Global router pointer for signal handler
var g_router: ?*router.Router = null;

/// Signal handler for graceful shutdown
fn handleSignal(sig: c_int) callconv(.C) void {
    _ = sig;
    std.debug.print("\n[MAIN] Received shutdown signal, stopping gracefully...\n", .{});
    if (g_router) |rt| {
        rt.stop();
    }
}

// =============================================================================
// IP Address Utilities
// =============================================================================

/// Convert u32 IP to dotted-decimal string (thread-unsafe, for debug only)
fn ip2str(ip: u32) [16]u8 {
    const b0 = (ip >> 24) & 0xFF;
    const b1 = (ip >> 16) & 0xFF;
    const b2 = (ip >> 8) & 0xFF;
    const b3 = ip & 0xFF;

    var buf: [16]u8 = undefined;
    const len = std.fmt.bufPrint(&buf, "{d}.{d}.{d}.{d}", .{ b0, b1, b2, b3 }) catch unreachable;
    buf[len.len] = 0;
    return buf;
}

/// Parse dotted-decimal IPv4 string to u32 (network byte order)
fn parseIp(ip_str: []const u8) !u32 {
    var val: u32 = 0;
    var parts: [4]u8 = undefined;
    var count: usize = 0;

    for (ip_str) |ch| {
        if (ch == '.') {
            if (count < 4) {
                parts[count] = @as(u8, @truncate(val));
                val = 0;
                count += 1;
            }
        } else {
            val = val * 10 + (ch - '0');
        }
    }
    if (count < 4) {
        parts[count] = @as(u8, @truncate(val));
    }

    // Network byte order: most significant byte first
    return @as(u32, parts[0]) << 24 |
        @as(u32, parts[1]) << 16 |
        @as(u32, parts[2]) << 8 |
        @as(u32, parts[3]);
}

// =============================================================================
// Command Line Arguments
// =============================================================================

const Args = struct {
    tun_ip: []const u8 = "10.0.0.1",
    tun_peer: []const u8 = "10.0.0.2",
    tun_prefix: u8 = 24,
    tun_mtu: u16 = 1500,
    proxy_addr: []const u8 = "",
    egress_iface: []const u8 = "",
    target_ip: []const u8 = "111.45.11.5",
    mock_port: u16 = 0,
    debug: bool = false,
};

/// Parse command line arguments
fn parseArgs() !Args {
    var args = Args{};
    var i: usize = 1;

    while (i < std.os.argv.len) : (i += 1) {
        const arg = std.mem.sliceTo(std.os.argv[i], 0);

        if (std.mem.eql(u8, arg, "--tun-ip") or std.mem.eql(u8, arg, "-i")) {
            i += 1;
            if (i < std.os.argv.len) {
                args.tun_ip = std.mem.sliceTo(std.os.argv[i], 0);
            }
        } else if (std.mem.eql(u8, arg, "--tun-mtu") or std.mem.eql(u8, arg, "-m")) {
            i += 1;
            if (i < std.os.argv.len) {
                args.tun_mtu = std.fmt.parseInt(u16, std.mem.sliceTo(std.os.argv[i], 0), 10) catch 1500;
            }
        } else if (std.mem.eql(u8, arg, "--prefix") or std.mem.eql(u8, arg, "-p")) {
            i += 1;
            if (i < std.os.argv.len) {
                args.tun_prefix = std.fmt.parseInt(u8, std.mem.sliceTo(std.os.argv[i], 0), 10) catch 24;
            }
        } else if (std.mem.eql(u8, arg, "--proxy") or std.mem.eql(u8, arg, "-x")) {
            i += 1;
            if (i < std.os.argv.len) {
                args.proxy_addr = std.mem.sliceTo(std.os.argv[i], 0);
            }
        } else if (std.mem.eql(u8, arg, "--egress") or std.mem.eql(u8, arg, "-e")) {
            i += 1;
            if (i < std.os.argv.len) {
                args.egress_iface = std.mem.sliceTo(std.os.argv[i], 0);
            }
        } else if (std.mem.eql(u8, arg, "--target") or std.mem.eql(u8, arg, "-t")) {
            i += 1;
            if (i < std.os.argv.len) {
                args.target_ip = std.mem.sliceTo(std.os.argv[i], 0);
            }
        } else if (std.mem.eql(u8, arg, "--mock-port") or std.mem.eql(u8, arg, "-M")) {
            i += 1;
            if (i < std.os.argv.len) {
                args.mock_port = std.fmt.parseInt(u16, std.mem.sliceTo(std.os.argv[i], 0), 10) catch 0;
            }
        } else if (std.mem.eql(u8, arg, "--debug") or std.mem.eql(u8, arg, "-d")) {
            args.debug = true;
        } else if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            printHelp();
            std.process.exit(0);
        }
    }

    return args;
}

fn printHelp() void {
    std.debug.print(
        \\Usage: tun2socks [OPTIONS]
        \\
        \\Options:
        \\  -i, --tun-ip IP       TUN interface IP (default: 10.0.0.1)
        \\  -P, --tun-peer PEER   TUN peer IP (default: 10.0.0.2)
        \\  -m, --tun-mtu MTU     TUN MTU (default: 1500)
        \\  -p, --prefix LEN      Prefix length (default: 24)
        \\  -x, --proxy ADDR      SOCKS5 proxy (default: none)
        \\  -e, --egress IFACE    Egress interface (auto-detect)
        \\  -t, --target IP       Target IP to route (default: 111.45.11.5)
        \\  -M, --mock-port PORT  Mock HTTP mode (bypass proxy)
        \\  -d, --debug           Enable debug logging
        \\  -h, --help            Show this help
        \\
        \\Examples:
        \\  sudo ./tun2socks -i 10.0.0.1 -x 127.0.0.1:1080 -t 111.45.11.5
        \\  sudo ./tun2socks -i 10.0.0.1 -M 8080 -t 111.45.11.5
        \\
    , .{});
}

// =============================================================================
// System Utilities
// =============================================================================

// POSIX geteuid for Unix systems
extern "c" fn geteuid() callconv(.C) c_uint;

// Windows IsUserAnAdmin (declared at comptime)
extern "c" fn IsUserAnAdmin() callconv(.Windows) c_uint;

/// Check if running with administrator/root privileges
fn isElevated() bool {
    if (builtin.os.tag == .windows) {
        return IsUserAnAdmin() != 0;
    }
    return geteuid() == 0;
}

// =============================================================================
// Route Callback
// =============================================================================

/// Route callback - defines routing policy for transparent proxy
///
/// Returns:
///   - .Socks5: Forward through SOCKS5 proxy
///   - .Direct: Forward directly (bypass proxy)
///   - .Local: Write back to TUN (local handling)
///   - .Nat: Forward with NAT translation
///   - .Drop: Silently drop packet
fn routeCallback(
    _: u32,
    _: u16,
    dst_ip: u32,
    _: u16,
    protocol: u8,
) router.RouteDecision {
    // Target IP: 111.45.11.5 (network byte order)
    const target_ip = (@as(u32, 111) << 24) | (@as(u32, 45) << 16) | (@as(u32, 11) << 8) | @as(u32, 5);

    // Rule 1: ICMP -> Local (auto-reply echo)
    if (protocol == 1) {
        return .Local;
    }

    // Rule 2: Private IPs -> Local (normal routing)
    if ((dst_ip & 0xFF000000) == 0x0A000000) return .Local; // 10.0.0.0/8
    if ((dst_ip & 0xFFF00000) == 0xAC100000) return .Local; // 172.16.0.0/12
    if ((dst_ip & 0xFFFF0000) == 0xC0A80000) return .Local; // 192.168.0.0/16
    if ((dst_ip & 0xFF000000) == 0x7F000000) return .Local; // 127.0.0.0/8
    if ((dst_ip & 0xFFFF0000) == 0xA9FE0000) return .Local; // 169.254.0.0/16

    // Rule 3: UDP -> Nat (NAT and forward)
    if (protocol == 17) {
        return .Nat;
    }

    // Rule 4: TCP to target -> Socks5 (if proxy configured) or Direct
    if (dst_ip == target_ip and protocol == 6) {
        return .Socks5;
    }

    // Rule 5: Multicast -> Drop
    if ((dst_ip & 0xF0000000) == 0xE0000000) {
        return .Drop;
    }

    // Rule 6: Default -> Local
    return .Local;
}

// =============================================================================
// Main Entry Point
// =============================================================================

pub fn main() !u8 {
    const allocator = std.heap.page_allocator;

    std.debug.print("\n=== ztun tun2socks - Transparent Proxy Forwarder ===\n\n", .{});

    // Check privileges
    if (!isElevated()) {
        std.debug.print("Error: This program requires root/administrator privileges.\n", .{});
        std.debug.print("Please run with sudo or as administrator.\n\n", .{});
        return 1;
    }

    // Parse arguments
    const args = parseArgs() catch {
        std.debug.print("Error: Invalid command line arguments\n", .{});
        return 1;
    };

    std.debug.print("Configuration:\n", .{});
    std.debug.print("  TUN IP:     {s}/{d}\n", .{ args.tun_ip, args.tun_prefix });
    std.debug.print("  TUN MTU:    {d}\n", .{args.tun_mtu});
    std.debug.print("  Target IP:  {s}\n", .{args.target_ip});
    std.debug.print("  Proxy:      {s}\n", .{if (args.proxy_addr.len > 0) args.proxy_addr else "none"});
    std.debug.print("  Mock:       {s}\n", .{if (args.mock_port > 0) "enabled" else "disabled"});
    std.debug.print("  Debug:      {s}\n\n", .{if (args.debug) "yes" else "no"});

    // Detect egress interface
    const egress_iface_name = if (args.egress_iface.len > 0) args.egress_iface else "en0";
    const iface_name_z = try allocator.dupeZ(u8, egress_iface_name);
    defer allocator.free(iface_name_z);

    const egress_ifindex = network.getInterfaceIndex(iface_name_z) catch blk: {
        std.debug.print("Warning: Failed to get interface index for '{s}', using 1\n", .{egress_iface_name});
        break :blk @as(u32, 1);
    };
    std.debug.print("Egress: {s} (index={d})\n\n", .{ egress_iface_name, egress_ifindex });

    // Parse IP addresses
    const tun_ip_nbo = parseIp(args.tun_ip) catch 0;
    const tun_peer_nbo = parseIp(args.tun_peer) catch 0;

    // Create TUN device
    std.debug.print("Creating TUN device...\n", .{});
    var opts = tun.Options{};
    opts.mtu = args.tun_mtu;
    opts.ipv4 = null;

    const device = tun.Device.create(opts) catch {
        std.debug.print("Error: Failed to create TUN device\n", .{});
        return 1;
    };
    defer device.destroy();

    device.setNonBlocking(true) catch {
        std.debug.print("Warning: Failed to set TUN to non-blocking mode\n", .{});
    };

    const tun_name = try device.name();
    const tun_ifindex = device.ifIndex() catch 0;
    std.debug.print("TUN: '{s}' (fd={}, ifindex={d})\n", .{ tun_name, device.getFd(), tun_ifindex });
    std.debug.print("  Local: {s} -> Peer: {s}\n\n", .{ ip2str(tun_ip_nbo), ip2str(tun_peer_nbo) });

    // Configure TUN IP on macOS
    if (builtin.os.tag == .macos or builtin.os.tag == .ios) {
        const tun_name_z = try allocator.dupeZ(u8, tun_name);
        defer allocator.free(tun_name_z);
        const tun_ip_z = try allocator.dupeZ(u8, args.tun_ip);
        defer allocator.free(tun_ip_z);
        const tun_peer_z = try allocator.dupeZ(u8, args.tun_peer);
        defer allocator.free(tun_peer_z);

        if (network.configureTunIp(tun_name_z, tun_ip_z) != 0) {
            std.debug.print("Warning: Failed to configure TUN IP\n", .{});
        }
        if (network.configureTunPeer(tun_name_z, tun_peer_z) != 0) {
            std.debug.print("Warning: Failed to configure TUN peer\n", .{});
        }
    }

    // Add route for target IP
    const target_cidr = try std.fmt.allocPrint(allocator, "{s}/32", .{args.target_ip});
    defer allocator.free(target_cidr);

    network.configSystemRoute(null, tun_name, target_cidr, 0) catch |err| {
        std.debug.print("Warning: Route configuration failed: {}, continuing...\n", .{err});
    };
    std.debug.print("Route: {s} -> {s}\n", .{ target_cidr, tun_name });

    // Create TUN configuration
    const tun_config = router.TunConfig{
        .name = try allocator.dupeZ(u8, tun_name),
        .ifindex = tun_ifindex,
        .ip = tun_ip_nbo,
        .peer = tun_peer_nbo,
        .prefix_len = args.tun_prefix,
        .mtu = args.tun_mtu,
        .fd = device.getFd(),
        .device_ops = null,
        .header_len = switch (builtin.os.tag) {
            .macos, .ios => 4, // macOS utun requires 4-byte header
            else => 0,
        },
    };

    // Create egress configuration
    const egress_config = router.EgressConfig{
        .name = iface_name_z,
        .ifindex = @intCast(if (egress_ifindex >= 0) egress_ifindex else 1),
        .ip = 0,
    };

    // Create proxy configuration (if proxy specified)
    var proxy_config: ?router.ProxyConfig = null;
    if (args.proxy_addr.len > 0) {
        proxy_config = .{
            .type = .Socks5,
            .addr = try allocator.dupeZ(u8, args.proxy_addr),
            .username = null,
            .password = null,
        };
    }

    // Create NAT configuration
    const nat_config = router.NatConfig{
        .egress_ip = 0,
        .port_range_start = 10000,
        .port_range_end = 60000,
        .timeout = 30,
    };

    // Create router configuration
    const router_config = router.RouterConfig{
        .tun = tun_config,
        .egress = egress_config,
        .proxy = proxy_config,
        .mock_enabled = args.mock_port > 0,
        .mock_port = args.mock_port,
        .route_cb = routeCallback,
        .tcp_pool_size = 4096,
        .udp_nat_size = 8192,
        .idle_timeout = 300,
        .udp_timeout = 30,
        .nat_config = nat_config,
    };

    std.debug.print("\nInitializing router...\n", .{});

    // Initialize router
    var rt = try router.Router.init(allocator, router_config);
    defer rt.deinit();

    // Setup signal handler for graceful shutdown
    g_router = &rt;
    const SIGINT = 2;
    const SIGTERM = 15;
    posix.signal(SIGINT, handleSignal) catch {};
    posix.signal(SIGTERM, handleSignal) catch {};

    std.debug.print("Router initialized successfully.\n", .{});
    std.debug.print("Starting event loop...\n", .{});
    std.debug.print("(Press Ctrl+C to stop)\n\n", .{});

    // Run router (blocking)
    rt.run();

    std.debug.print("\nRouter stopped.\n", .{});
    const stats = rt.stats();
    std.debug.print("Statistics:\n", .{});
    std.debug.print("  TCP connections: {d}\n", .{stats.tcp_connections});
    std.debug.print("  UDP sessions:   {d}\n", .{stats.udp_sessions});
    std.debug.print("  Packets fwd:    {d}\n", .{stats.packets_forwarded});
    std.debug.print("  Packets drop:   {d}\n", .{stats.packets_dropped});
    std.debug.print("  Bytes RX:       {d}\n", .{stats.bytes_rx});
    std.debug.print("  Bytes TX:       {d}\n\n", .{stats.bytes_tx});

    return 0;
}
