//! tun2sock.zig - Transparent proxy TUN to SOCKS5 forwarding application
//!
//! This application demonstrates how to use the ztun.router module to forward
//! VPN traffic through a SOCKS5 proxy.
//!
//! Usage: sudo ./tun2sock --tun-ip 10.0.0.1 --proxy 127.0.0.1:1080
//!
//! Architecture:
//!   Application Layer (this file)
//!   - Creates TUN device with provided name and IP
//!   - Implements route callback for routing decisions
//!   - Uses network.zig for route configuration (passes strings to C layer)
//!
//!   Network Layer (network.zig)
//!   - Accepts IP/prefix strings from Zig
//!   - Passes strings to C layer for route configuration
//!   - C layer handles all byte order conversions internally
//!
//!   Router Layer (ztun.router)
//!   - libxev event loop for async I/O
//!   - TUN async read
//!   - TCP connection pool
//!   - UDP NAT table
//!   - Proxy forwarder (SOCKS5 backend)

const std = @import("std");
const builtin = @import("builtin");
const tun = @import("tun");
const router = @import("router");
const network = @import("network");

// POSIX geteuid for Unix systems
extern "c" fn geteuid() callconv(.C) c_uint;

// Windows IsUserAnAdmin check - returns BOOL (1 = admin, 0 = not admin)
extern "c" fn IsUserAnAdmin() callconv(.Windows) c_uint;

// C library system() function for running shell commands
extern fn system(cmd: [*:0]const u8) c_int;

/// Check if running with administrator/root privileges
fn isElevated() bool {
    if (builtin.os.tag == .windows) {
        return IsUserAnAdmin() != 0;
    }
    return geteuid() == 0;
}

// Command line arguments - all as strings to pass to C layer
const Args = struct {
    tun_ip: []const u8 = "10.0.0.1",
    tun_peer: []const u8 = "10.0.0.2",
    tun_prefix: []const u8 = "24",
    tun_mtu: []const u8 = "1500",
    proxy_addr: []const u8 = "127.0.0.1:1080",
    egress_iface: []const u8 = "",
    target_ip: []const u8 = "111.45.11.5",
    debug: bool = false,
};

/// Parse command line arguments
fn parseArgs(_: std.mem.Allocator) !Args {
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
                args.tun_mtu = std.mem.sliceTo(std.os.argv[i], 0);
            }
        } else if (std.mem.eql(u8, arg, "--prefix") or std.mem.eql(u8, arg, "-p")) {
            i += 1;
            if (i < std.os.argv.len) {
                args.tun_prefix = std.mem.sliceTo(std.os.argv[i], 0);
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
        } else if (std.mem.eql(u8, arg, "--tun-peer") or std.mem.eql(u8, arg, "-P")) {
            i += 1;
            if (i < std.os.argv.len) {
                args.tun_peer = std.mem.sliceTo(std.os.argv[i], 0);
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
        \\Usage: tun2sock [OPTIONS]
        \\
        \\Options:
        \\  -i, --tun-ip IP       TUN interface IP address (default: 10.0.0.1)
        \\  -P, --tun-peer PEER   TUN peer/destination IP (default: 10.0.0.2)
        \\  -m, --tun-mtu MTU     TUN device MTU (default: 1500)
        \\  -p, --prefix LEN      IPv4 prefix length (default: 24)
        \\  -x, --proxy ADDR      SOCKS5 proxy address (default: 127.0.0.1:1080)
        \\  -e, --egress IFACE    Egress interface name (auto-detect if empty)
        \\  -t, --target IP       Target IP to route through TUN (default: 111.45.11.5)
        \\  -d, --debug           Enable debug logging
        \\  -h, --help            Show this help message
        \\
        \\Note:
        \\  On macOS, TUN device name is auto-generated (utunX).
        \\  Route configuration passes IP strings to C layer for byte order handling.
        \\
        \\Example:
        \\  sudo ./tun2sock --tun-ip 10.0.0.1 --target 111.45.11.5 --proxy 127.0.0.1:1080
        \\
    , .{});
}

/// Route callback - application defines routing policy for transparent proxy
///
/// Routing rules:
///   1. ICMP (protocol=1) -> Local (auto-reply echo)
///   2. Private IPs (RFC 1918) -> Local (normal routing)
///   3. UDP (protocol=17) -> Nat (NAT and forward)
///   4. TCP to target IP -> Socks5 (proxy)
///   5. Multicast -> Drop (silently)
///   6. Default -> Local (normal routing)
///
/// Note: All IPs in network byte order (big-endian)
fn routeCallback(
    _: u32,
    _: u16,
    dst_ip: u32,
    _: u16,
    protocol: u8,
) router.RouteDecision {
    // Target IP: 111.45.11.5 (network byte order: 0x6F2D0B05)
    const target_ip = (@as(u32, 111) << 24) | (@as(u32, 45) << 16) | (@as(u32, 11) << 8) | @as(u32, 5);

    // Rule 1: ICMP protocol -> Local (auto-reply echo request)
    if (protocol == 1) {
        return .Local;
    }

    // Rule 2: Private IP ranges -> Local (normal routing)
    // 10.0.0.0/8
    if ((dst_ip & 0xFF000000) == 0x0A000000) return .Local;
    // 172.16.0.0/12
    if ((dst_ip & 0xFFF00000) == 0xAC100000) return .Local;
    // 192.168.0.0/16
    if ((dst_ip & 0xFFFF0000) == 0xC0A80000) return .Local;
    // 127.0.0.0/8 (loopback)
    if ((dst_ip & 0xFF000000) == 0x7F000000) return .Local;
    // 169.254.0.0/16 (link-local)
    if ((dst_ip & 0xFFFF0000) == 0xA9FE0000) return .Local;

    // Rule 3: UDP protocol -> Nat (NAT and forward all UDP)
    if (protocol == 17) {
        return .Nat;
    }

    // Rule 4: TCP to target IP -> Socks5 (proxy)
    if (dst_ip == target_ip and protocol == 6) {
        return .Socks5;
    }

    // Rule 5: Multicast (224.0.0.0/4) -> Drop
    if ((dst_ip & 0xF0000000) == 0xE0000000) {
        return .Drop;
    }

    // Rule 6: Default -> Local (normal routing through system)
    return .Local;
}

// Main entry point
pub fn main() !u8 {
    const allocator = std.heap.page_allocator;

    std.debug.print("\n=== ztun tun2sock - Transparent Proxy Forwarder ===\n\n", .{});

    // Check if running with elevated privileges
    if (!isElevated()) {
        if (builtin.os.tag == .windows) {
            std.debug.print("Warning: This program requires administrator privileges.\n", .{});
            std.debug.print("Please run as administrator.\n\n", .{});
        } else {
            std.debug.print("Warning: This program requires root privileges.\n", .{});
            std.debug.print("Please run with sudo.\n\n", .{});
        }
        return 1;
    }

    // Parse command line arguments
    const args = parseArgs(allocator) catch {
        std.debug.print("Error: Invalid command line arguments\n", .{});
        return 1;
    };

    std.debug.print("Configuration:\n", .{});
    std.debug.print("  TUN IP:       {s}/{s}\n", .{ args.tun_ip, args.tun_prefix });
    std.debug.print("  TUN MTU:      {s}\n", .{args.tun_mtu});
    std.debug.print("  Target IP:    {s}/32\n", .{args.target_ip});
    std.debug.print("  Proxy:        {s}\n", .{args.proxy_addr});
    std.debug.print("  Debug:        {s}\n\n", .{if (args.debug) "yes" else "no"});

    // Detect egress interface
    const egress_iface_name = if (args.egress_iface.len > 0) args.egress_iface else "en0";
    const iface_name_z = try allocator.dupeZ(u8, egress_iface_name);
    defer allocator.free(iface_name_z);
    const egress_ifindex = blk: {
        if (network.getInterfaceIndex(iface_name_z)) |idx| {
            break :blk idx;
        } else |err| {
            std.debug.print("Warning: Failed to get interface index for '{s}': {}, using 1\n", .{egress_iface_name, err});
            break :blk @as(u32, 1);
        }
    };
    std.debug.print("Egress: {s} (index={d})\n\n", .{ egress_iface_name, egress_ifindex });

    // Create TUN device
    std.debug.print("Creating TUN device...\n", .{});

    // Parse prefix length
    const prefix_len = std.fmt.parseInt(u8, args.tun_prefix, 10) catch 24;

    // Create Options struct
    var opts = tun.Options{};
    opts.mtu = std.fmt.parseInt(u16, args.tun_mtu, 10) catch 1500;
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
    std.debug.print("TUN device '{s}' created successfully.\n", .{tun_name});
    std.debug.print("  FD: {}\n", .{device.getFd()});

    const mtu_val = device.mtu() catch 1500;
    std.debug.print("  MTU: {d}\n\n", .{mtu_val});

    // Get TUN interface index
    const tun_ifindex = device.ifIndex() catch 0;
    std.debug.print("TUN interface index: {d} (name='{s}')\n", .{ tun_ifindex, tun_name });

    // Configure TUN interface IP address and peer (required before adding routes on macOS)
    if (builtin.os.tag == .macos or builtin.os.tag == .ios) {
        const tun_name_z = try allocator.dupeZ(u8, tun_name);
        defer allocator.free(tun_name_z);
        const tun_ip_z = try allocator.dupeZ(u8, args.tun_ip);
        defer allocator.free(tun_ip_z);
        const tun_peer_z = try allocator.dupeZ(u8, args.tun_peer);
        defer allocator.free(tun_peer_z);
        std.debug.print("Configuring TUN IP: {s} -> {s}\n", .{ tun_name, args.tun_ip });
        if (network.configureTunIp(tun_name_z, tun_ip_z) != 0) {
            std.debug.print("Warning: Failed to configure TUN IP, routes may fail\n", .{});
        }
        std.debug.print("Configuring TUN peer: {s} -> {s}\n", .{ tun_name, args.tun_peer });
        if (network.configureTunPeer(tun_name_z, tun_peer_z) != 0) {
            std.debug.print("Warning: Failed to configure TUN peer, routing may not work correctly\n", .{});
        }
    }

    // Configure route: target_ip/32 -> TUN (via C layer)
    // For macOS utun point-to-point interfaces, use gateway=0 (direct route)
    // The -iface option in route command associates route with the interface directly
    const target_cidr = try std.fmt.allocPrint(allocator, "{s}/32", .{args.target_ip});
    defer allocator.free(target_cidr);

    // For point-to-point utun, use gateway=0 (direct interface route)
    // This matches test_tun.zig's BSD Routing Socket implementation
    const gateway_ip: []const u8 = "0.0.0.0";

    network.configSystemRoute(
        null,
        tun_name,
        target_cidr,
        network.parseIp(gateway_ip) catch 0,
    ) catch |err| {
        std.debug.print("Warning: Route configuration failed: {}, continuing...\n", .{err});
    };
    std.debug.print("Route configured: {s} -> {s} (gateway={s}, direct)\n", .{ target_cidr, args.tun_ip, gateway_ip });

    // Add route for TUN IP itself via TUN interface (symmetric routing for ICMP replies)
    // This ensures reply packets to 10.0.0.1 can be routed back through the TUN interface
    // For point-to-point utun, use gateway=0 (direct route)
    if (builtin.os.tag == .macos or builtin.os.tag == .ios) {
        const tun_ip_cidr = try std.fmt.allocPrint(allocator, "{s}/32", .{args.tun_ip});
        defer allocator.free(tun_ip_cidr);

        network.configSystemRoute(
            null,
            tun_name,
            tun_ip_cidr,
            0,  // No gateway needed for direct interface route
        ) catch |err| {
            std.debug.print("Warning: TUN IP route configuration failed: {}, continuing...\n", .{err});
        };
        std.debug.print("Route configured: {s} -> {s} (local, direct)\n", .{ tun_ip_cidr, tun_name });
    }

    // Parse TUN IP and peer for router configuration
    const tun_ip_nbo = network.parseIp(args.tun_ip) catch 0;
    const tun_peer_nbo = network.parseIp(args.tun_peer) catch 0;

    // Create TUN configuration for router
    const tun_config = router.TunConfig{
        .name = try allocator.dupeZ(u8, tun_name),
        .ifindex = tun_ifindex,
        .ip = tun_ip_nbo,
        .peer = tun_peer_nbo,
        .prefix_len = prefix_len,
        .mtu = opts.mtu orelse 1500,
        .fd = device.getFd(),
        .device_ops = null,
        .header_len = switch (builtin.os.tag) {
            .macos, .ios => 4,  // macOS utun requires 4-byte header on write
            else => 0,
        },
    };

    // Create egress configuration
    const egress_config = router.EgressConfig{
        .name = iface_name_z,
        .ifindex = if (egress_ifindex >= 0) @intCast(egress_ifindex) else 1,
        .ip = 0,  // Will be resolved by router
    };

    // Create proxy configuration
    const proxy_config = router.ProxyConfig{
        .type = .Socks5,
        .addr = try allocator.dupeZ(u8, args.proxy_addr),
        .username = null,
        .password = null,
    };

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
        .route_cb = routeCallback,
        .tcp_pool_size = 4096,
        .udp_nat_size = 8192,
        .idle_timeout = 300,
        .udp_timeout = 30,
        .nat_config = nat_config,
    };

    std.debug.print("Initializing router...\n\n", .{});

    // Initialize router
    var rt = try router.Router.init(allocator, router_config);
    defer rt.deinit();

    std.debug.print("Router initialized successfully.\n", .{});
    std.debug.print("Starting event loop...\n", .{});
    std.debug.print("(Press Ctrl+C to stop)\n\n", .{});

    // Run router (blocking)
    rt.run();

    std.debug.print("\nRouter stopped.\n", .{});
    const stats = rt.stats();
    std.debug.print("Statistics:\n", .{});
    std.debug.print("  Packets forwarded: {d}\n", .{stats.packets_forwarded});
    std.debug.print("  Packets dropped:   {d}\n", .{stats.packets_dropped});
    std.debug.print("  Bytes received:    {d}\n", .{stats.bytes_rx});
    std.debug.print("  Bytes sent:        {d}\n\n", .{stats.bytes_tx});

    return 0;
}
