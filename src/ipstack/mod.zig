//! mod.zig - StaticIpstack Main Module
//!
//! Pure static IP stack implementation with zero heap allocations.
//! Provides TCP/UDP/ICMP protocol handling with event-driven callbacks.

const std = @import("std");
const builtin = @import("builtin");

// Re-export protocol modules (imports match build.zig module names)
pub const checksum = @import("ipstack_checksum");
pub const ipv4 = @import("ipstack_ipv4");
pub const ipv6 = @import("ipstack_ipv6");
pub const tcp = @import("ipstack_tcp");
pub const udp = @import("ipstack_udp");
pub const icmp = @import("ipstack_icmp");
pub const icmpv6 = @import("ipstack_icmpv6");
pub const connection = @import("ipstack_connection");
pub const callbacks = @import("ipstack_callbacks");

// Re-export SystemStack (TunStack implementation for StaticIpstack)
pub const stack_system = @import("stack_system");

// Platform detection
const is_windows = builtin.os.tag == .windows;
const is_macos = builtin.os.tag == .macos;

// Configuration constants
const MAX_CONNECTIONS = 1024;
const PACKET_BUF_SIZE = 65536;
const DEFAULT_MSS = 1460;
const DEFAULT_IDLE_TIMEOUT = 300; // seconds

// Statistics
pub const Statistics = struct {
    tcp_connections: u32 = 0,
    tcp_active: u32 = 0,
    udp_packets: u32 = 0,
    icmp_packets: u32 = 0,
    icmpv6_packets: u32 = 0,
    ipv6_packets: u32 = 0,
    dropped_packets: u32 = 0,
    checksum_errors: u32 = 0,
    connection_timeouts: u32 = 0,
};

// Configuration
pub const Config = struct {
    /// Local IP address (network byte order)
    local_ip: u32,
    /// Pseudo source IP for replies (network byte order)
    pseudo_src_ip: u32,
    /// Callback handlers
    callbacks: callbacks.Callbacks,
    /// Idle timeout in seconds (default: 300)
    idle_timeout: u32 = DEFAULT_IDLE_TIMEOUT,
    /// Maximum connections (default: 1024)
    max_connections: usize = MAX_CONNECTIONS,
};

// IPv6 configuration (for dual-stack)
pub const Ipv6Config = struct {
    /// Local IPv6 address (16 bytes)
    local_ip: [16]u8,
    /// Enable IPv6 support
    enabled: bool = false,
};

// Static IP stack context
pub const StaticIpstack = struct {
    // Connection table (static allocation)
    connections: [MAX_CONNECTIONS]connection.Connection,
    conn_used: [MAX_CONNECTIONS]bool,

    // Scratch buffer for packet building (65536 bytes)
    packet_buf: [PACKET_BUF_SIZE]u8,

    // Configuration
    config: Config,

    // IPv6 configuration
    ipv6_config: Ipv6Config,

    // Statistics
    stats: Statistics,

    // Current timestamp (set by application)
    current_time: u32,

    // ISN generator state
    isn_counter: u32,
};

// Error types
pub const Error = error{
    InvalidParameter,
    ConnectionTableFull,
    ConnectionNotFound,
    InvalidPacket,
    ChecksumError,
    BufferTooSmall,
    NotSupported,
};

/// Initialize the static IP stack
/// ipstack: Pointer to uninitialized StaticIpstack
/// cfg: Configuration
/// Returns: error on failure
pub fn init(ipstack: *StaticIpstack, cfg: Config) void {
    // Zero all memory
    ipstack.* = undefined;

    // Set configuration
    ipstack.config = cfg;

    // Initialize IPv6 config (disabled by default)
    ipstack.ipv6_config = .{ .local_ip = [_]u8{0} ** 16, .enabled = false };

    // Initialize statistics
    ipstack.stats = .{};

    // Initialize timestamp
    ipstack.current_time = 0;

    // Initialize ISN counter with random-ish value
    ipstack.isn_counter = 0x12345678;

    // Mark all connections as unused
    @memset(ipstack.conn_used[0..], false);
}

/// Reset the IP stack (no deallocation needed)
pub fn reset(ipstack: *StaticIpstack) void {
    @memset(ipstack.conn_used[0..], false);
    ipstack.stats = .{};
}

/// Set IPv6 configuration
pub fn setIpv6Config(ipstack: *StaticIpstack, cfg: Ipv6Config) void {
    ipstack.ipv6_config = cfg;
}

/// Update timestamp (called by application)
pub fn updateTimestamp(ipstack: *StaticIpstack, timestamp: u32) void {
    ipstack.current_time = timestamp;
}

/// Process incoming IPv4 packet
/// ipstack: IP stack context
/// data: Raw IP packet data (starts with IPv4 header)
/// len: Packet length
/// Returns: error on failure
pub fn processIpv4Packet(ipstack: *StaticIpstack, data: [*]const u8, len: usize) Error!void {
    if (len < ipv4.HDR_MIN_SIZE) {
        return error.InvalidPacket;
    }

    const ip_info = ipv4.parseHeader(data, len) orelse {
        ipstack.stats.dropped_packets += 1;
        return error.InvalidPacket;
    };

    // Route to appropriate protocol handler
    switch (ip_info.protocol) {
        ipv4.PROTO_TCP => {
            try processTcpPacket(ipstack, data, ip_info);
        },
        ipv4.PROTO_UDP => {
            try processUdpPacket(ipstack, data, ip_info);
        },
        ipv4.PROTO_ICMP => {
            try processIcmpPacket(ipstack, data, ip_info);
        },
        else => {
            // Raw packet callback
            if (ipstack.config.callbacks.onIpv4Packet) |cb| {
                const payload = data[ip_info.header_len..ip_info.total_len];
                cb(ip_info.src_ip, ip_info.dst_ip, ip_info.protocol, payload);
            }
        },
    }
}

/// Process TCP packet
fn processTcpPacket(ipstack: *StaticIpstack, data: [*]const u8, ip_info: ipv4.PacketInfo) Error!void {
    const tcp_offset = ip_info.header_len;
    const tcp_len = ip_info.total_len - ip_info.header_len;

    if (tcp_len < tcp.HDR_MIN_SIZE) {
        return error.InvalidPacket;
    }

    const tcp_info = tcp.parseHeader(data + tcp_offset, tcp_len) orelse {
        ipstack.stats.dropped_packets += 1;
        return error.InvalidPacket;
    };

    // Build connection key
    const conn_key = connection.ConnKey{
        .src_ip = ip_info.dst_ip,
        .src_port = tcp_info.dst_port,
        .dst_ip = ip_info.src_ip,
        .dst_port = tcp_info.src_port,
    };

    // Handle based on flags
    if (tcp_info.is_syn) {
        try handleTcpSyn(ipstack, &conn_key, tcp_info);
    } else if (tcp_info.is_rst) {
        handleTcpRst(ipstack, &conn_key);
    } else if (tcp_info.is_fin) {
        handleTcpFin(ipstack, &conn_key, tcp_info);
    } else if (tcp_info.payload_len > 0) {
        // Data packet - find connection
        try handleTcpData(ipstack, &conn_key, tcp_info, data + tcp_offset + tcp_info.header_len);
    } else {
        // ACK-only packet
        handleTcpAck(ipstack, &conn_key, tcp_info);
    }
}

/// Handle TCP SYN (connection request)
fn handleTcpSyn(ipstack: *StaticIpstack, key: *const connection.ConnKey, tcp_info: tcp.PacketInfo) Error!void {
    // Check if reverse connection exists (outgoing connection)
    const rev_key = connection.reverseKey(key);
    if (findConnection(ipstack, &rev_key)) |conn| {
        // This is a SYN-ACK response
        if (conn.state == .SynSent) {
            conn.state = .Established;
            conn.remote_seq = tcp_info.seq_num;
            conn.local_seq +%= 1; // Our SYN was ACKed
            ipstack.stats.tcp_active += 1;
            callbacks.invokeTcpEstablished(&ipstack.config.callbacks, conn);
        }
        return;
    }

    // New incoming connection - check accept callback
    if (!callbacks.invokeTcpAccept(
        &ipstack.config.callbacks,
        key.dst_ip,
        key.dst_port,
        key.src_ip,
        key.src_port,
    )) {
        // Rejected - send RST (would need packet building)
        return;
    }

    // Create new connection in LISTEN state
    const slot = findFreeConnection(ipstack) orelse {
        ipstack.stats.dropped_packets += 1;
        return error.ConnectionTableFull;
    };

    const conn = &ipstack.connections[slot];
    connection.initListen(conn, key.dst_ip, key.dst_port, key.src_ip, key.src_port);
    ipstack.conn_used[slot] = true;

    // Transition to SYN-RECEIVED
    conn.state = .SynReceived;
    conn.local_seq = generateIsn(ipstack);
    conn.remote_seq = tcp_info.seq_num;

    // Send SYN-ACK (would need to build packet and send via callback)
    ipstack.stats.tcp_connections += 1;
    ipstack.stats.tcp_active += 1;
}

/// Handle TCP RST
fn handleTcpRst(ipstack: *StaticIpstack, key: *const connection.ConnKey) void {
    if (findConnection(ipstack, key)) |conn| {
        callbacks.invokeTcpReset(&ipstack.config.callbacks, conn);
        connection.reset(conn);
        ipstack.conn_used[findConnIndex(ipstack, conn) orelse return] = false;
        ipstack.stats.tcp_active -|= 1;
    }
}

/// Handle TCP FIN
fn handleTcpFin(ipstack: *StaticIpstack, key: *const connection.ConnKey, _: tcp.PacketInfo) void {
    if (findConnection(ipstack, key)) |conn| {
        conn.remote_seq +%= 1; // FIN consumes a sequence number
        // Transition state based on current state
        switch (conn.state) {
            .Established => {
                conn.state = .CloseWait;
                callbacks.invokeTcpClose(&ipstack.config.callbacks, conn);
            },
            .FinWait1 => {
                conn.state = .Closing;
            },
            .FinWait2 => {
                conn.state = .TimeWait;
            },
            else => {},
        }
    }
}

/// Handle TCP data packet
fn handleTcpData(
    ipstack: *StaticIpstack,
    key: *const connection.ConnKey,
    tcp_info: tcp.PacketInfo,
    data: [*]const u8,
) Error!void {
    const conn = findConnection(ipstack, key) orelse {
        ipstack.stats.dropped_packets += 1;
        return error.ConnectionNotFound;
    };

    // Validate sequence number (simplified)
    // In a full implementation, would check against receive window

    // Update activity
    conn.last_activity = ipstack.current_time;

    // Invoke data callback
    const payload = data[0..tcp_info.payload_len];
    callbacks.invokeTcpData(&ipstack.config.callbacks, conn, payload);
}

/// Handle TCP ACK-only packet
fn handleTcpAck(ipstack: *StaticIpstack, key: *const connection.ConnKey, tcp_info: tcp.PacketInfo) void {
    if (findConnection(ipstack, key)) |conn| {
        conn.remote_acked = tcp_info.ack_num;
        // Would handle ACK-based state transitions here
    }
}

/// Process UDP packet
fn processUdpPacket(ipstack: *StaticIpstack, data: [*]const u8, ip_info: ipv4.PacketInfo) Error!void {
    const udp_offset = ip_info.header_len;
    const udp_len = ip_info.total_len - ip_info.header_len;

    if (udp_len < udp.HDR_SIZE) {
        return error.InvalidPacket;
    }

    const udp_info = udp.parseHeader(data + udp_offset, udp_len) orelse {
        ipstack.stats.dropped_packets += 1;
        return error.InvalidPacket;
    };

    ipstack.stats.udp_packets += 1;

    const payload = data + udp_offset + udp.HDR_SIZE;
    callbacks.invokeUdp(
        &ipstack.config.callbacks,
        ip_info.src_ip,
        udp_info.src_port,
        ip_info.dst_ip,
        udp_info.dst_port,
        payload[0..udp_info.payload_len],
    );
}

/// Process ICMP packet
fn processIcmpPacket(ipstack: *StaticIpstack, data: [*]const u8, ip_info: ipv4.PacketInfo) Error!void {
    const icmp_offset = ip_info.header_len;
    const icmp_len = ip_info.total_len - ip_info.header_len;

    if (icmp_len < icmp.HDR_SIZE) {
        return error.InvalidPacket;
    }

    const icmp_info = icmp.parseHeader(data + icmp_offset, icmp_len) orelse {
        ipstack.stats.checksum_errors += 1;
        return error.ChecksumError;
    };

    ipstack.stats.icmp_packets += 1;

    // Handle echo request
    if (icmp_info.type == icmp.TYPE_ECHO_REQUEST) {
        const icmp_payload = data[icmp_offset + icmp.HDR_SIZE ..icmp_len];
        if (callbacks.invokeIcmpEcho(
            &ipstack.config.callbacks,
            ip_info.src_ip,
            ip_info.dst_ip,
            icmp_info.identifier,
            icmp_info.sequence,
            icmp_payload,
        )) {
            // Send echo reply
            try sendIcmpEchoReply(ipstack, data + icmp_offset, icmp_len, ip_info.src_ip);
        }
    } else {
        // Other ICMP types
        if (ipstack.config.callbacks.onIcmp) |cb| {
            cb(ip_info.src_ip, ip_info.dst_ip, icmp_info.type, icmp_info.code, &.{});
        }
    }
}

/// Send ICMP Echo Reply
fn sendIcmpEchoReply(ipstack: *StaticIpstack, req: [*]const u8, req_len: usize, dst_ip: u32) Error!void {
    if (req_len < icmp.HDR_SIZE) {
        return error.InvalidPacket;
    }

    const req_header = @as(*const icmp.IcmpEcho, @ptrCast(@alignCast(req)));
    const payload = if (req_len > icmp.HDR_SIZE) req[icmp.HDR_SIZE..req_len] else &[_]u8{};

    const total_len = icmp.HDR_SIZE + payload.len;
    if (total_len > PACKET_BUF_SIZE) {
        return error.BufferTooSmall;
    }

    // Build reply in scratch buffer
    const reply = &ipstack.packet_buf;
    const reply_len = icmp.buildEchoReply(reply[0..].ptr, req_header.identifier, req_header.sequence, payload);

    // Build IP header
    const ip_len = ipv4.buildHeaderWithChecksum(
        reply[reply_len..].ptr,
        ipstack.config.local_ip,
        dst_ip,
        ipv4.PROTO_ICMP,
        reply_len,
    );

    // Send via write callback (not implemented in this core module)
    // Application would register a write callback for this
    _ = ip_len;
}

/// Process incoming IPv6 packet
/// ipstack: IP stack context
/// data: Raw IP packet data (starts with IPv6 header)
/// len: Packet length
/// Returns: error on failure
pub fn processIpv6Packet(ipstack: *StaticIpstack, data: [*]const u8, len: usize) Error!void {
    if (!ipstack.ipv6_config.enabled) {
        return error.NotSupported;
    }

    if (len < ipv6.HDR_SIZE) {
        return error.InvalidPacket;
    }

    const ip_info = ipv6.parseHeader(data, len) orelse {
        ipstack.stats.dropped_packets += 1;
        return error.InvalidPacket;
    };

    ipstack.stats.ipv6_packets += 1;

    // Route to appropriate protocol handler
    switch (ip_info.next_header) {
        ipv6.NH_TCP => {
            // TCP over IPv6 not fully implemented - delegate to raw callback
            if (ipstack.config.callbacks.onIpv6Packet) |cb| {
                const payload = data[ipv6.HDR_SIZE..len];
                cb(&ip_info.src_addr, &ip_info.dst_addr, ip_info.next_header, payload);
            }
        },
        ipv6.NH_UDP => {
            // UDP over IPv6
            try processIpv6UdpPacket(ipstack, data, len, &ip_info);
        },
        ipv6.NH_ICMPV6 => {
            try processIcmpv6Packet(ipstack, data, len, &ip_info);
        },
        else => {
            // Raw packet callback
            if (ipstack.config.callbacks.onIpv6Packet) |cb| {
                const payload = data[ipv6.HDR_SIZE..len];
                cb(&ip_info.src_addr, &ip_info.dst_addr, ip_info.next_header, payload);
            }
        },
    }
}

/// Process UDP packet over IPv6
fn processIpv6UdpPacket(ipstack: *StaticIpstack, data: [*]const u8, len: usize, ip_info: *const ipv6.PacketInfo) Error!void {
    const udp_offset = ipv6.HDR_SIZE;
    const udp_len = len - udp_offset;

    if (udp_len < udp.HDR_SIZE) {
        return error.InvalidPacket;
    }

    const udp_info = udp.parseHeader(data + udp_offset, udp_len) orelse {
        ipstack.stats.dropped_packets += 1;
        return error.InvalidPacket;
    };

    ipstack.stats.udp_packets += 1;

    // IPv6 UDP doesn't have checksum verification in this simplified implementation
    const payload = data + udp_offset + udp.HDR_SIZE;
    if (ipstack.config.callbacks.onIpv6Udp) |cb| {
        cb(&ip_info.src_addr, udp_info.src_port, &ip_info.dst_addr, udp_info.dst_port, payload[0..udp_info.payload_len]);
    }
}

/// Process ICMPv6 packet
fn processIcmpv6Packet(ipstack: *StaticIpstack, data: [*]const u8, len: usize, ip_info: *const ipv6.PacketInfo) Error!void {
    const icmp_offset = ipv6.HDR_SIZE;
    const icmp_len = len - icmp_offset;

    if (icmp_len < icmpv6.HDR_SIZE) {
        return error.InvalidPacket;
    }

    const icmp_info = icmpv6.parseHeader(data + icmp_offset, icmp_len, &ip_info.src_addr, &ip_info.dst_addr) orelse {
        ipstack.stats.checksum_errors += 1;
        return error.ChecksumError;
    };

    ipstack.stats.icmpv6_packets += 1;

    // Handle echo request
    if (icmp_info.type == icmpv6.TYPE_ECHO_REQUEST) {
        const icmp_payload = if (icmp_len > icmpv6.HDR_SIZE) data[icmp_offset + icmpv6.HDR_SIZE ..len] else &[_]u8{};
        if (ipstack.config.callbacks.onIcmpv6Echo) |cb| {
            cb(&ip_info.src_addr, &ip_info.dst_addr, icmp_info.identifier, icmp_info.sequence, icmp_payload);
        }
    } else if (icmpv6.needsResponse(icmp_info.type)) {
        // Handle other query types that need responses
        if (ipstack.config.callbacks.onIcmpv6) |cb| {
            cb(&ip_info.src_addr, &ip_info.dst_addr, icmp_info.type, icmp_info.code, &.{});
        }
    } else {
        // Error messages - forward if callback exists
        if (ipstack.config.callbacks.onIcmpv6) |cb| {
            cb(&ip_info.src_addr, &ip_info.dst_addr, icmp_info.type, icmp_info.code, &.{});
        }
    }
}

/// Send ICMPv6 Echo Reply
/// ipstack: IP stack context
/// src_addr: Original sender IPv6 address
/// dst_addr: TUN interface IPv6 address
/// identifier: ICMPv6 identifier from request
/// sequence: ICMPv6 sequence from request
/// payload: Payload from request
/// reply_buf: Output buffer for reply
/// Returns: Total reply length
pub fn buildIcmpv6EchoReply(
    ipstack: *StaticIpstack,
    src_addr: *const [16]u8,
    dst_addr: *const [16]u8,
    identifier: u16,
    sequence: u16,
    payload: []const u8,
    reply_buf: []u8,
) Error!usize {
    _ = ipstack; // Reserved for future use
    const total_len = icmpv6.HDR_SIZE + payload.len;
    if (total_len > reply_buf.len) {
        return error.BufferTooSmall;
    }

    // Build ICMPv6 echo reply with checksum
    const len = icmpv6.buildEchoReply(reply_buf.ptr, identifier, sequence, payload, dst_addr, src_addr);
    return len;
}

/// Send IPv6 UDP packet
pub fn ipv6UdpSend(
    ipstack: *StaticIpstack,
    src_addr: *const [16]u8,
    src_port: u16,
    dst_addr: *const [16]u8,
    dst_port: u16,
    data: []const u8,
    buf: []u8,
) Error!usize {
    _ = ipstack; // Reserved for future use
    const udp_len = udp.HDR_SIZE + data.len;
    const total_len = ipv6.HDR_SIZE + udp_len;

    if (total_len > buf.len) {
        return error.BufferTooSmall;
    }

    // Build IPv6 header
    ipv6.buildHeader(buf.ptr, src_addr, dst_addr, ipv6.NH_UDP, udp_len);

    // Build UDP header with checksum
    const udp_offset = ipv6.HDR_SIZE;
    _ = udp.buildHeaderWithChecksum(
        buf[udp_offset..].ptr,
        @as(*const [16]u8, @ptrCast(src_addr))[0..16].ptr,
        @as(*const [16]u8, @ptrCast(dst_addr))[0..16].ptr,
        src_port,
        dst_port,
        data,
    );

    return total_len;
}

/// Find free connection slot
fn findFreeConnection(ipstack: *StaticIpstack) ?usize {
    for (0..MAX_CONNECTIONS) |i| {
        if (!ipstack.conn_used[i]) {
            return i;
        }
    }
    return null;
}

/// Find connection by key
fn findConnection(ipstack: *StaticIpstack, key: *const connection.ConnKey) ?*connection.Connection {
    for (0..MAX_CONNECTIONS) |i| {
        if (ipstack.conn_used[i]) {
            if (connection.keyMatch(&ipstack.connections[i], key)) {
                return &ipstack.connections[i];
            }
        }
    }
    return null;
}

/// Find connection index
fn findConnIndex(ipstack: *StaticIpstack, conn: *connection.Connection) ?usize {
    const base = @intFromPtr(&ipstack.connections[0]);
    const target = @intFromPtr(conn);
    const offset = target - base;
    const index = offset / @sizeOf(connection.Connection);
    if (index < MAX_CONNECTIONS) {
        return index;
    }
    return null;
}

/// Generate Initial Sequence Number
fn generateIsn(ipstack: *StaticIpstack) u32 {
    ipstack.isn_counter +%= 1;
    return ipstack.isn_counter;
}

/// Clean up timed out connections
pub fn cleanupTimeouts(ipstack: *StaticIpstack) void {
    for (0..MAX_CONNECTIONS) |i| {
        if (ipstack.conn_used[i]) {
            const conn = &ipstack.connections[i];
            if (connection.hasTimedOut(conn, ipstack.current_time, ipstack.config.idle_timeout)) {
                callbacks.invokeTcpReset(&ipstack.config.callbacks, conn);
                connection.reset(conn);
                ipstack.conn_used[i] = false;
                ipstack.stats.connection_timeouts += 1;
                if (ipstack.stats.tcp_active > 0) {
                    ipstack.stats.tcp_active -= 1;
                }
            }
        }
    }
}

/// Get statistics
pub fn getStatistics(ipstack: *StaticIpstack) Statistics {
    return ipstack.stats;
}

/// Send TCP data through existing connection
pub fn tcpSend(
    ipstack: *StaticIpstack,
    conn: *connection.Connection,
    data: []const u8,
) Error!void {
    if (conn.state != .Established and conn.state != .CloseWait) {
        return error.InvalidState;
    }

    // Build TCP packet in scratch buffer
    if (ipv4.HDR_SIZE + tcp.HDR_MIN_SIZE + data.len > PACKET_BUF_SIZE) {
        return error.BufferTooSmall;
    }

    const pkt = &ipstack.packet_buf;

    // Build IP header
    const ip_offset = ipv4.buildHeader(
        pkt[0..].ptr,
        ipstack.config.local_ip,
        conn.src_ip,
        ipv4.PROTO_TCP,
        tcp.HDR_MIN_SIZE + data.len,
    );

    // Build TCP header
    _ = tcp.buildHeaderWithChecksum(
        pkt[ip_offset..].ptr,
        ipstack.config.local_ip,
        conn.src_ip,
        conn.dst_port,
        conn.src_port,
        conn.local_seq,
        conn.remote_seq,
        tcp.FLAG_PSH | tcp.FLAG_ACK,
        @as(u16, @truncate(conn.remote_window)),
        data,
    );
}

/// Send UDP packet
pub fn udpSend(
    ipstack: *StaticIpstack,
    src_ip: u32,
    src_port: u16,
    dst_ip: u32,
    dst_port: u16,
    data: []const u8,
) Error!void {
    const total_len = udp.HDR_SIZE + data.len;
    if (total_len > PACKET_BUF_SIZE) {
        return error.BufferTooSmall;
    }

    const pkt = &ipstack.packet_buf;

    // Build IP header
    const ip_offset = ipv4.buildHeader(
        pkt[0..].ptr,
        src_ip,
        dst_ip,
        ipv4.PROTO_UDP,
        total_len,
    );

    // Build UDP header with checksum
    _ = udp.buildHeaderWithChecksum(
        pkt[ip_offset..].ptr,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        data,
    );
}

// Unit tests
test "StaticIpstack init and reset" {
    var ipstack: StaticIpstack = undefined;

    const cfg = .{
        .local_ip = 0xC0A80101,
        .pseudo_src_ip = 0xC0A80102,
        .callbacks = .{},
        .idle_timeout = 300,
    };

    init(&ipstack, cfg);
    try std.testing.expectEqual(@as(u32, 0), ipstack.stats.tcp_connections);
    try std.testing.expect(ipstack.isn_counter != 0);

    reset(&ipstack);
    try std.testing.expectEqual(@as(u32, 0), ipstack.stats.tcp_connections);
}

test "StaticIpstack cleanup timeouts" {
    var ipstack: StaticIpstack = undefined;

    init(&ipstack, .{
        .local_ip = 0xC0A80101,
        .pseudo_src_ip = 0xC0A80102,
        .callbacks = .{},
        .idle_timeout = 10,
    });

    // Add a connection
    const slot = findFreeConnection(&ipstack) orelse return error.SkipZigTest;
    const conn = &ipstack.connections[slot];
    connection.initListen(conn, 0xC0A80101, 12345, 0xC0A80102, 80);
    ipstack.conn_used[slot] = true;

    // Set old timestamp
    ipstack.current_time = 100;
    conn.last_activity = 50; // 50 seconds ago

    // Cleanup
    cleanupTimeouts(&ipstack);

    // Connection should be cleaned up
    try std.testing.expect(!ipstack.conn_used[slot]);
    try std.testing.expectEqual(@as(u32, 1), ipstack.stats.connection_timeouts);
}

test "StaticIpstack find connection" {
    var ipstack: StaticIpstack = undefined;

    init(&ipstack, .{
        .local_ip = 0xC0A80101,
        .pseudo_src_ip = 0xC0A80102,
        .callbacks = .{},
    });

    // Add a connection
    const slot = findFreeConnection(&ipstack) orelse return error.SkipZigTest;
    const conn = &ipstack.connections[slot];
    connection.initListen(conn, 0xC0A80101, 12345, 0xC0A80102, 80);
    ipstack.conn_used[slot] = true;

    // Find it
    const key = &connection.ConnKey{
        .src_ip = 0xC0A80101,
        .src_port = 12345,
        .dst_ip = 0xC0A80102,
        .dst_port = 80,
    };

    const found = findConnection(&ipstack, key);
    try std.testing.expect(found == conn);

    // Not found
    const wrong_key = &connection.ConnKey{
        .src_ip = 0xC0A80101,
        .src_port = 99999,
        .dst_ip = 0xC0A80102,
        .dst_port = 80,
    };
    try std.testing.expect(findConnection(&ipstack, wrong_key) == null);
}
