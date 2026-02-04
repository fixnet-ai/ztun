//! tun2sock.zig - Transparent proxy TUN to SOCKS5 forwarding application
//!
//! This application demonstrates how to use the ztun.router module to forward
//! VPN traffic through a SOCKS5 proxy.
//!
//! Usage: sudo ./tun2sock --tun-name tun0 --tun-ip 10.0.0.1 --proxy 127.0.0.1:1080
//!
//! Architecture:
//!   Application Layer (this file)
//!   - Creates TUN device with provided name and IP
//!   - Detects egress interface for direct forwarding
//!   - Implements route callback for routing decisions
//!   - Passes all configuration to Router.init()
//!
//!   Router Layer (ztun.router)
//!   - libxev event loop for async I/O
//!   - TUN async read
//!   - TCP connection pool
//!   - UDP NAT table
//!   - Proxy forwarder (SOCKS5 backend)
//!
//! Key Design:
//!   - Router is a FIXED forwarding engine with NO extension logic
//!   - All configuration (TUN params, egress, proxy, route callback) from application
//!   - Router doesn't create TUN or set system routes

const std = @import("std");
const builtin = @import("builtin");
const tun = @import("tun");
const router = @import("router");

// Command line arguments
const Args = struct {
    tun_name: []const u8 = "tun0",
    tun_ip: []const u8 = "10.0.0.1",
    tun_mtu: u16 = 1500,
    prefix_len: u8 = 24,
    proxy_addr: []const u8 = "127.0.0.1:1080",
    egress_iface: []const u8 = "",
    debug: bool = false,
};

// Parse command line arguments
fn parseArgs(_: std.mem.Allocator) !Args {
    var args = Args{};

    var i: usize = 1;
    while (i < std.os.argv.len) : (i += 1) {
        const arg = std.mem.sliceTo(std.os.argv[i], 0);

        if (std.mem.eql(u8, arg, "--tun-name") or std.mem.eql(u8, arg, "-n")) {
            i += 1;
            if (i < std.os.argv.len) {
                args.tun_name = std.mem.sliceTo(std.os.argv[i], 0);
            }
        } else if (std.mem.eql(u8, arg, "--tun-ip") or std.mem.eql(u8, arg, "-i")) {
            i += 1;
            if (i < std.os.argv.len) {
                args.tun_ip = std.mem.sliceTo(std.os.argv[i], 0);
            }
        } else if (std.mem.eql(u8, arg, "--tun-mtu") or std.mem.eql(u8, arg, "-m")) {
            i += 1;
            if (i < std.os.argv.len) {
                args.tun_mtu = try std.fmt.parseInt(u16, std.mem.sliceTo(std.os.argv[i], 0), 10);
            }
        } else if (std.mem.eql(u8, arg, "--prefix") or std.mem.eql(u8, arg, "-p")) {
            i += 1;
            if (i < std.os.argv.len) {
                args.prefix_len = try std.fmt.parseInt(u8, std.mem.sliceTo(std.os.argv[i], 0), 10);
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
        \\  -n, --tun-name NAME   TUN device name (default: tun0)
        \\  -i, --tun-ip IP       TUN interface IP address (default: 10.0.0.1)
        \\  -m, --tun-mtu MTU     TUN device MTU (default: 1500)
        \\  -p, --prefix LEN      IPv4 prefix length (default: 24)
        \\  -x, --proxy ADDR      SOCKS5 proxy address (default: 127.0.0.1:1080)
        \\  -e, --egress IFACE    Egress interface name (auto-detect if empty)
        \\  -d, --debug           Enable debug logging
        \\  -h, --help            Show this help message
        \\
        \\Example:
        \\  sudo ./tun2sock --tun-name tun0 --tun-ip 10.0.0.1 --proxy 127.0.0.1:1080
        \\
    , .{});
}

// Convert IP string to u32 (network byte order)
fn parseIpv4(ip_str: []const u8) !u32 {
    var parts: [4]u8 = undefined;
    var part_idx: usize = 0;
    var val: u32 = 0;
    var dot_count: usize = 0;

    for (ip_str) |c| {
        if (c == '.') {
            if (part_idx >= 4) return error.InvalidIp;
            parts[part_idx] = @as(u8, @truncate(val));
            val = 0;
            part_idx += 1;
            dot_count += 1;
        } else if (c >= '0' and c <= '9') {
            val = val * 10 + (c - '0');
            if (val > 255) return error.InvalidIp;
        } else {
            return error.InvalidIp;
        }
    }

    // Last part
    if (part_idx >= 4) return error.InvalidIp;
    parts[part_idx] = @as(u8, @truncate(val));

    if (dot_count != 3) return error.InvalidIp;

    // Combine to u32 (network byte order: parts[0] is most significant)
    return @as(u32, parts[0]) << 24 | @as(u32, parts[1]) << 16 | @as(u32, parts[2]) << 8 | @as(u32, parts[3]);
}

// Parse proxy address (ip:port)
fn parseProxyAddr(addr: []const u8) !struct { ip: u32, port: u16 } {
    const colon_idx = std.mem.lastIndexOf(u8, addr, ":") orelse return error.InvalidProxyAddr;

    const ip_str = addr[0..colon_idx];
    const port_str = addr[colon_idx + 1 ..];

    const ip = try parseIpv4(ip_str);
    const port = try std.fmt.parseInt(u16, port_str, 10);

    if (port == 0) return error.InvalidPort;

    return .{ .ip = ip, .port = port };
}

// Route callback - application defines routing policy
fn routeCallback(
    src_ip: u32,
    src_port: u16,
    dst_ip: u32,
    dst_port: u16,
    protocol: u8,
) router.RouteDecision {
    _ = src_ip;
    _ = src_port;

    // Private IP ranges (RFC 1918)
    const private_10 = dst_ip & 0xFF000000 == 0x0A000000; // 10.0.0.0/8
    const private_172 = dst_ip & 0xFFF00000 == 0xAC100000; // 172.16.0.0/12
    const private_192 = dst_ip & 0xFFFF0000 == 0xC0A80000; // 192.168.0.0/16
    const loopback = dst_ip & 0xFF000000 == 0x7F000000; // 127.0.0.0/8
    const linklocal = dst_ip & 0xFFFF0000 == 0xA9FE0000; // 169.254.0.0/16

    // Drop multicast
    const multicast = dst_ip & 0xF0000000 == 0xE0000000; // 224.0.0.0/4

    // Local/private traffic - handle locally
    if (private_10 or private_172 or private_192 or loopback or linklocal) {
        return .Local;
    }

    // Multicast - drop
    if (multicast) {
        return .Drop;
    }

    // UDP traffic to port 53 (DNS) - forward directly for resolution
    if (protocol == 17 and dst_port == 53) {
        return .Direct;
    }

    // UDP - use NAT for forwarding
    if (protocol == 17) {
        return .Nat;
    }

    // TCP - forward through SOCKS5 proxy
    return .Socks5;
}

// Detect default egress interface
fn detectEgressInterface(allocator: std.mem.Allocator) !struct { name: [:0]const u8, ip: u32, ifindex: u32 } {
    // Return en0 as default - egress IP detection is optional
    const name = try allocator.dupeZ(u8, "en0");
    return .{ .name = name, .ip = 0, .ifindex = 1 };
}

/// Main entry point
pub fn main() !u8 {
    const allocator = std.heap.page_allocator;

    std.debug.print("\n=== ztun tun2sock - Transparent Proxy Forwarder ===\n\n", .{});

    // Check if running as root (required for TUN)
    if (builtin.os.tag == .macos or builtin.os.tag == .linux) {
        const euid = std.os.linux.geteuid();
        if (euid != 0) {
            std.debug.print("Warning: This program requires root privileges.\n", .{});
            std.debug.print("Please run with sudo.\n\n", .{});
            return 1;
        }
    }

    // Parse command line arguments
    const args = parseArgs(allocator) catch {
        std.debug.print("Error: Invalid command line arguments\n", .{});
        return 1;
    };

    std.debug.print("Configuration:\n", .{});
    std.debug.print("  TUN name:     {s}\n", .{args.tun_name});
    std.debug.print("  TUN IP:       {s}/{d}\n", .{args.tun_ip, args.prefix_len});
    std.debug.print("  TUN MTU:      {d}\n", .{args.tun_mtu});
    std.debug.print("  Proxy:        {s}\n", .{args.proxy_addr});
    std.debug.print("  Debug:        {s}\n\n", .{if (args.debug) "yes" else "no"});

    // Parse IP addresses
    const tun_ip = try parseIpv4(args.tun_ip);
    const proxy = try parseProxyAddr(args.proxy_addr);

    std.debug.print("Parsed addresses:\n", .{});
    std.debug.print("  TUN IP:       0x{X}\n", .{tun_ip});
    std.debug.print("  Proxy IP:     0x{X}\n", .{proxy.ip});
    std.debug.print("  Proxy Port:   {d}\n\n", .{proxy.port});

    // Detect egress interface - use default for now
    const egress = .{
        .name = allocator.dupeZ(u8, "en0") catch "en0",
        .ip = 0,
        .ifindex = 1,
    };

    std.debug.print("Egress interface: {s} (index={d}, ip=0x{X})\n\n", .{
        egress.name,
        egress.ifindex,
        egress.ip,
    });

    // Create TUN device
    std.debug.print("Creating TUN device...\n", .{});

    var builder = tun.DeviceBuilder{};
    _ = builder.setName(args.tun_name);
    _ = builder.setMtu(args.tun_mtu);

    // Parse gateway IP from TUN IP (use first address as gateway)
    const gateway_ip = tun_ip | 0x01000000; // x.x.x.1
    _ = builder.setIpv4(.{ @as(u8, @truncate(gateway_ip >> 24)), @as(u8, @truncate(gateway_ip >> 16)), @as(u8, @truncate(gateway_ip >> 8)), @as(u8, @truncate(gateway_ip)) }, args.prefix_len, null);

    const device = builder.build() catch {
        std.debug.print("Error: Failed to create TUN device '{s}'\n", .{args.tun_name});
        std.debug.print("Make sure the device doesn't already exist.\n", .{});
        return 1;
    };
    defer device.destroy();

    std.debug.print("TUN device '{s}' created successfully.\n", .{args.tun_name});
    std.debug.print("  FD: {}\n", .{device.getFd()});
    const mtu_val = device.mtu() catch 1500;
    std.debug.print("  MTU: {d}\n\n", .{mtu_val});

    // Get TUN interface index
    const tun_ifindex = 0;

    // Create TUN configuration for router
    const tun_config = router.TunConfig{
        .name = try allocator.dupeZ(u8, args.tun_name),
        .ifindex = tun_ifindex,
        .ip = tun_ip,
        .prefix_len = args.prefix_len,
        .mtu = args.tun_mtu,
        .fd = device.getFd(),
    };

    // Create egress configuration
    const egress_config = router.EgressConfig{
        .name = egress.name,
        .ifindex = egress.ifindex,
        .ip = egress.ip,
    };

    // Create proxy configuration
    const proxy_config = router.ProxyConfig{
        .type = .Socks5,
        .addr = try allocator.dupeZ(u8, args.proxy_addr),
        .username = null,
        .password = null,
    };

    // Create NAT configuration (use egress IP for NAT source)
    const nat_config = router.NatConfig{
        .egress_ip = egress.ip,
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
