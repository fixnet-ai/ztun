//! socks5.zig - SOCKS5 Proxy Client with libxev
//!
//! Implements a complete SOCKS5 proxy client with async I/O support.
//! Uses libxev's completion callbacks for non-blocking I/O.
//!
//! Usage:
//!   1. Create a Socks5Client with create()
//!   2. Call connect() to establish connection to SOCKS5 proxy
//!   3. Use send() and recv() to forward data through the proxy
//!
//! UDP Associate Support:
//!   1. Call associateUdp() to establish UDP relay binding
//!   2. Use sendUdp() to send datagrams through proxy
//!   3. Handle recvUdp() for incoming datagrams from proxy

const std = @import("std");
const xev = @import("xev");

/// SOCKS5 connection state
pub const Socks5State = enum(u8) {
    /// Initial state, need to connect
    Disconnected = 0,
    /// Connecting to proxy
    Connecting = 1,
    /// Sent greeting, waiting for ack
    Greeting = 2,
    /// Sent connect request, waiting for ack
    Request = 3,
    /// Ready to forward data
    Ready = 4,
    /// Error state
    Error = 5,
    /// Connection closed
    Closed = 6,
};

/// SOCKS5 errors
pub const Socks5Error = error{
    /// Invalid data received
    InvalidData,
    /// Invalid SOCKS version
    InvalidVersion,
    /// Authentication required
    AuthRequired,
    /// Connection failed
    ConnectionFailed,
    /// Socket operation failed
    SocketFailed,
    /// Not connected
    NotConnected,
    /// Operation not ready
    NotReady,
};

/// Callback for handling proxied data (received from target server)
pub const DataCallback = *const fn (userdata: ?*anyopaque, data: []const u8, client: *Socks5Client) void;

/// Callback when SOCKS5 tunnel is established
pub const TunnelReadyCallback = *const fn (userdata: ?*anyopaque, client: *Socks5Client) void;

/// Format IP address for logging
fn fmtIp(ip: u32) [15]u8 {
    var buf: [15]u8 = undefined;
    _ = std.fmt.bufPrint(&buf, "{}.{}.{}.{}", .{
        @as(u8, @truncate(ip >> 24)),
        @as(u8, @truncate(ip >> 16)),
        @as(u8, @truncate(ip >> 8)),
        @as(u8, @truncate(ip)),
    }) catch unreachable;
    return buf;
}

// ============================================================================
// SOCKS5 UDP Associate Client
// ============================================================================

/// UDP Associate state
pub const UdpAssociateState = enum(u8) {
    /// Initial state
    Disconnected = 0,
    /// Request sent, waiting for reply
    Binding = 1,
    /// UDP relay ready
    Ready = 2,
    /// Error state
    Error = 3,
    /// Closed
    Closed = 4,
};

/// UDP datagram callback
pub const UdpDatagramCallback = *const fn (userdata: ?*anyopaque, data: []const u8, src_ip: u32, src_port: u16) void;

/// SOCKS5 UDP Associate client for UDP forwarding through proxy
pub const Socks5UdpAssociate = struct {
    /// libxev event loop
    loop: *xev.Loop,

    /// UDP socket to proxy
    udp_sock: std.posix.socket_t = undefined,

    /// Completion for async operations
    completion: xev.Completion = .{},

    /// Connection state
    state: UdpAssociateState = .Disconnected,

    /// Proxy TCP connection (for UDP associate handshake)
    tcp_conn: *Socks5Client,

    /// Bound UDP port on proxy (from UDP associate reply)
    bound_port: u16 = 0,

    /// Read/Write buffers
    read_buf: [65536]u8 = undefined,
    write_buf: [65536]u8 = undefined,

    /// User-provided context
    userdata: ?*anyopaque = null,

    /// Callbacks
    on_udp_data: ?UdpDatagramCallback = null,
    on_error: ?*const fn (userdata: ?*anyopaque, err: Socks5Error) void,

    /// Create a new UDP Associate client
    pub fn create(
        allocator: std.mem.Allocator,
        loop: *xev.Loop,
        tcp_conn: *Socks5Client,
    ) !*Socks5UdpAssociate {
        const client = try allocator.create(Socks5UdpAssociate);
        client.* = Socks5UdpAssociate{
            .loop = loop,
            .tcp_conn = tcp_conn,
            .on_error = tcp_conn.on_error orelse onDefaultError,
        };
        return client;
    }

    /// Destroy a UDP Associate client
    pub fn destroy(self: *Socks5UdpAssociate, allocator: std.mem.Allocator) void {
        if (self.udp_sock != -1) {
            std.posix.close(self.udp_sock);
        }
        allocator.destroy(self);
    }

    /// Set callbacks
    pub fn setCallbacks(
        self: *Socks5UdpAssociate,
        userdata: ?*anyopaque,
        on_udp_data: ?UdpDatagramCallback,
        on_error: ?*const fn (userdata: ?*anyopaque, err: Socks5Error) void,
    ) void {
        self.userdata = userdata;
        self.on_udp_data = on_udp_data;
        if (on_error) |cb| self.on_error = cb;
    }

    /// Establish UDP associate binding via SOCKS5 proxy
    pub fn associate(
        self: *Socks5UdpAssociate,
    ) Socks5Error!void {
        std.debug.print("\n[SOCKS5-UDP] ============================================\n", .{});
        std.debug.print("[SOCKS5-UDP] associate() called\n", .{});

        // Create UDP socket
        self.udp_sock = std.posix.socket(
            self.tcp_conn.proxy_addr.any.family,
            std.posix.SOCK.DGRAM | std.posix.SOCK.NONBLOCK,
            0,
        ) catch |err| {
            std.debug.print("[SOCKS5-UDP-ERROR] socket() failed: {}\n", .{err});
            return error.SocketFailed;
        };

        std.debug.print("[SOCKS5-UDP] socket created: fd={}\n", .{self.udp_sock});

        // Connect UDP socket to proxy (for sending UDP datagrams)
        std.posix.connect(self.udp_sock, &self.tcp_conn.proxy_addr.any, self.tcp_conn.proxy_addr.getOsSockLen()) catch |err| {
            std.debug.print("[SOCKS5-UDP-ERROR] connect() failed: {}\n", .{err});
            std.posix.close(self.udp_sock);
            return error.ConnectionFailed;
        };

        std.debug.print("[SOCKS5-UDP] UDP socket connected to proxy\n", .{});
        std.debug.print("[SOCKS5-UDP-EXIT] ============================================\n\n", .{});
    }

    /// Send UDP datagram through SOCKS5 proxy
    /// Builds SOCKS5 UDP request header and sends to proxy
    pub fn sendDatagram(
        self: *Socks5UdpAssociate,
        data: []const u8,
        dst_ip: u32,
        dst_port: u16,
    ) Socks5Error!usize {
        if (self.udp_sock == -1) return error.NotConnected;

        std.debug.print("[SOCKS5-UDP] sendDatagram: {} bytes to {s}:{}\n", .{ data.len, fmtIp(dst_ip), dst_port });

        // Build SOCKS5 UDP request header
        // Format: RSV(2) + ATYP(1) + DST.ADDR + DST.PORT(2) + DATA
        var offset: usize = 0;

        // RSV = 0
        self.write_buf[0] = 0;
        self.write_buf[1] = 0;
        offset += 2;

        // ATYP = IPv4 (0x01)
        self.write_buf[offset] = 0x01;
        offset += 1;

        // DST.ADDR = IPv4 address (network byte order)
        std.mem.writeInt(u32, self.write_buf[offset .. offset + 4], dst_ip, .big);
        offset += 4;

        // DST.PORT (network byte order)
        std.mem.writeInt(u16, self.write_buf[offset .. offset + 2], dst_port, .big);
        offset += 2;

        // Copy data
        @memcpy(self.write_buf[offset .. offset + data.len], data);

        const total_len = offset + data.len;

        // Send to proxy via UDP socket
        const sent = std.posix.send(self.udp_sock, self.write_buf[0..total_len], 0) catch |err| {
            std.debug.print("[SOCKS5-UDP-ERROR] send() failed: {}\n", .{err});
            return error.SocketFailed;
        };

        std.debug.print("[SOCKS5-UDP] Sent {} bytes to proxy\n", .{sent});
        return sent;
    }

    /// Submit async read for UDP datagrams from proxy
    pub fn submitRead(self: *Socks5UdpAssociate) void {
        if (self.udp_sock == -1) return;

        self.completion = .{
            .op = .{
                .read = .{
                    .fd = self.udp_sock,
                    .buffer = .{ .slice = &self.read_buf },
                },
            },
            .userdata = self,
            .callback = onUdpRead,
        };
        self.loop.add(&self.completion);
    }

    /// Check if ready for UDP forwarding
    pub fn isReady(self: *Socks5UdpAssociate) bool {
        return self.state == .Ready and self.udp_sock != -1;
    }

    /// Close the UDP associate
    pub fn close(self: *Socks5UdpAssociate) void {
        if (self.udp_sock >= 0) {
            std.posix.close(self.udp_sock);
        }
        self.udp_sock = -1;
        self.state = .Closed;
    }
};

/// Default error handler
fn onDefaultError(userdata: ?*anyopaque, err: Socks5Error) void {
    _ = userdata;
    std.debug.print("[SOCKS5-UDP-ERROR] {}\n", .{err});
}

/// UDP read callback - receive datagrams from proxy
fn onUdpRead(
    userdata: ?*anyopaque,
    loop: *xev.Loop,
    completion: *xev.Completion,
    result: xev.Result,
) xev.CallbackAction {
    _ = loop;
    _ = completion;

    const self: *Socks5UdpAssociate = @ptrCast(@alignCast(userdata orelse return .disarm));

    const n = result.read catch |err| {
        std.debug.print("[SOCKS5-UDP-ERROR] read failed: {}\n", .{err});
        self.submitRead();
        return .disarm;
    };

    if (n == 0) {
        self.submitRead();
        return .disarm;
    }

    std.debug.print("[SOCKS5-UDP] Received {} bytes from proxy\n", .{n});

    // Parse SOCKS5 UDP response header
    // Format: RSV(2) + ATYP(1) + DST.ADDR + DST.PORT(2) + DATA
    if (n < 10) {
        std.debug.print("[SOCKS5-UDP-WARN] Packet too small: {} bytes\n", .{n});
        self.submitRead();
        return .disarm;
    }

    // Skip RSV (2 bytes)
    const atyp = self.read_buf[2];

    var src_ip: u32 = 0;
    var src_port: u16 = 0;
    var data_offset: usize = 0;

    if (atyp == 0x01) { // IPv4
        src_ip = std.mem.readInt(u32, self.read_buf[3..7], .big);
        src_port = std.mem.readInt(u16, self.read_buf[7..9], .big);
        data_offset = 9;
    } else if (atyp == 0x03) { // Domain name
        const name_len = self.read_buf[3];
        const name_offset = 4 + name_len;
        src_port = std.mem.readInt(u16, self.read_buf[name_offset .. name_offset + 2], .big);
        // For domain names, we can't easily resolve, skip for now
        data_offset = name_offset + 2;
    } else if (atyp == 0x04) { // IPv6
        src_ip = 0; // TODO: Handle IPv6
        src_port = std.mem.readInt(u16, self.read_buf[21..23], .big);
        data_offset = 23;
    } else {
        std.debug.print("[SOCKS5-UDP-WARN] Unknown ATYP: {x:0>2}\n", .{atyp});
        self.submitRead();
        return .disarm;
    }

    const data = self.read_buf[data_offset..n];
    std.debug.print("[SOCKS5-UDP] From {s}:{} ({} bytes data)\n", .{ fmtIp(src_ip), src_port, data.len });

    // Call callback with parsed data
    if (self.on_udp_data) |cb| {
        cb(self.userdata, data, src_ip, src_port);
    }

    // Continue reading
    self.submitRead();

    return .disarm;
}

/// UDP Associate errors
pub const UdpAssociateError = error{
    NotReady,
    SocketFailed,
    ConnectionFailed,
};

/// SOCKS5 proxy connection
pub const Socks5Client = struct {
    /// libxev event loop
    loop: *xev.Loop,

    /// Socket to SOCKS5 proxy
    sock: std.posix.socket_t = undefined,

    /// Completion for async operations
    completion: xev.Completion = .{},

    /// Connection state
    state: Socks5State = .Disconnected,

    /// Proxy server address
    proxy_addr: std.net.Address,

    /// Target server info (for CONNECT request)
    dst_ip: u32 = 0,
    dst_port: u16 = 0,

    /// Connection 4-tuple (for routing responses back to TUN)
    src_ip: u32 = 0,
    src_port: u16 = 0,

    /// Read/Write buffers (pre-allocated, allocation-free)
    read_buf: [65536]u8 = undefined,
    read_buf_len: usize = 0,
    write_buf: [65536]u8 = undefined,

    /// Pending data to send after connection established
    pending_data: ?[]const u8 = null,

    /// User-provided context
    userdata: ?*anyopaque = null,

    /// Callbacks
    on_data: ?DataCallback = null,
    on_tunnel_ready: ?TunnelReadyCallback = null,
    on_ready: ?*const fn (userdata: ?*anyopaque) void = null,
    on_error: ?*const fn (userdata: ?*anyopaque, err: Socks5Error) void = null,

    /// Create a new SOCKS5 client
    pub fn create(
        allocator: std.mem.Allocator,
        loop: *xev.Loop,
        proxy_addr: std.net.Address,
    ) !*Socks5Client {
        const client = try allocator.create(Socks5Client);
        client.* = Socks5Client{
            .loop = loop,
            .proxy_addr = proxy_addr,
        };
        return client;
    }

    /// Destroy a SOCKS5 client
    pub fn destroy(self: *Socks5Client, allocator: std.mem.Allocator) void {
        if (self.sock != -1) {
            std.posix.close(self.sock);
        }
        allocator.destroy(self);
    }

    /// Set callbacks for client events
    pub fn setCallbacks(
        self: *Socks5Client,
        userdata: ?*anyopaque,
        on_data: ?DataCallback,
        on_tunnel_ready: ?TunnelReadyCallback,
        on_ready: ?*const fn (?*anyopaque, *Socks5Client) void,
        on_error: ?*const fn (?*anyopaque, Socks5Error, *Socks5Client) void,
    ) void {
        self.userdata = userdata;
        self.on_data = on_data;
        self.on_tunnel_ready = on_tunnel_ready;
        self.on_ready = on_ready;
        self.on_error = on_error;
    }

    /// Connect to SOCKS5 proxy asynchronously
    pub fn connectAsync(
        self: *Socks5Client,
        target_ip: u32,
        target_port: u16,
    ) Socks5Error!void {
        std.debug.print("\n[SOCKS5] ============================================\n", .{});
        std.debug.print("[SOCKS5] connectAsync() called\n", .{});
        std.debug.print("[SOCKS5] target_ip={s} target_port={}\n", .{ fmtIp(target_ip), target_port });

        // Store target info
        self.dst_ip = target_ip;
        self.dst_port = target_port;
        self.pending_data = null;
        self.state = .Connecting;
        std.debug.print("[SOCKS5] state set to Connecting\n", .{});

        // Create socket with NONBLOCK
        self.sock = std.posix.socket(
            self.proxy_addr.any.family,
            std.posix.SOCK.STREAM | std.posix.SOCK.NONBLOCK,
            0,
        ) catch |err| {
            std.debug.print("[SOCKS5-ERROR] socket() failed: {}\n", .{err});
            return error.SocketFailed;
        };

        std.debug.print("[SOCKS5] socket created: fd={}\n", .{self.sock});

        // Start async connect using libxev
        self.completion = .{
            .op = .{
                .connect = .{
                    .socket = self.sock,
                    .addr = self.proxy_addr,
                },
            },
            .userdata = self,
            .callback = onConnect,
        };
        self.loop.add(&self.completion);
        std.debug.print("[SOCKS5] async connect submitted to loop\n", .{});
        std.debug.print("[SOCKS5-EXIT] ============================================\n\n", .{});
    }

    /// Connect to SOCKS5 proxy and establish tunnel
    pub fn connect(
        self: *Socks5Client,
        target_ip: u32,
        target_port: u16,
        data: ?[]const u8,
    ) Socks5Error!void {
        std.debug.print("\n[SOCKS5] ============================================\n", .{});
        std.debug.print("[SOCKS5] connect() called at {}\n", .{std.time.nanoTimestamp()});
        std.debug.print("[SOCKS5] target_ip={s} target_port={}\n", .{ fmtIp(target_ip), target_port });
        std.debug.print("[SOCKS5] pending_data={}\n", .{data != null});

        // Store target info
        self.dst_ip = target_ip;
        self.dst_port = target_port;
        self.pending_data = data;
        self.state = .Connecting;
        std.debug.print("[SOCKS5] state set to Connecting\n", .{});

        // Create socket with NONBLOCK
        self.sock = std.posix.socket(
            self.proxy_addr.any.family,
            std.posix.SOCK.STREAM | std.posix.SOCK.NONBLOCK,
            0,
        ) catch |err| {
            std.debug.print("[SOCK] socket() failed: {}\nS5-ERROR", .{err});
            return error.SocketFailed;
        };

        std.debug.print("[SOCKS5] socket created: fd={}\n", .{self.sock});
        std.debug.print("[SOCKS5] proxy_addr family={} port={}\n", .{ self.proxy_addr.any.family, self.proxy_addr.getPort() });

        // Start async connect
        std.debug.print("[SOCKS5] Adding connect completion to loop...\n", .{});
        self.completion = .{
            .op = .{
                .connect = .{
                    .socket = self.sock,
                    .addr = self.proxy_addr,
                },
            },
            .userdata = self,
            .callback = onConnect,
        };
        self.loop.add(&self.completion);
        std.debug.print("[SOCKS5] connect completion added\n", .{});
        std.debug.print("[SOCKS5-EXIT] ============================================\n\n", .{});
    }

    /// Blocking connect to SOCKS5 proxy (for SYN handling)
    pub fn connectBlocking(
        self: *Socks5Client,
        target_ip: u32,
        target_port: u16,
    ) Socks5Error!void {
        std.debug.print("\n[SOCKS5-BLOCK] ============================================\n", .{});
        std.debug.print("[SOCKS5-BLOCK] connectBlocking() called\n", .{});
        std.debug.print("[SOCKS5-BLOCK] target_ip={s} target_port={}\n", .{ fmtIp(target_ip), target_port });

        // Store target info
        self.dst_ip = target_ip;
        self.dst_port = target_port;
        self.pending_data = null;
        self.state = .Connecting;
        std.debug.print("[SOCKS5-BLOCK] state set to Connecting\n", .{});

        // Create blocking socket
        self.sock = std.posix.socket(
            self.proxy_addr.any.family,
            std.posix.SOCK.STREAM,
            0,
        ) catch |err| {
            std.debug.print("[SOCKS5-BLOCK-ERROR] socket() failed: {}\n", .{err});
            return error.SocketFailed;
        };

        std.debug.print("[SOCKS5-BLOCK] socket created: fd={}\n", .{self.sock});

        // Blocking connect
        std.debug.print("[SOCKS5-BLOCK] Calling blocking connect...\n", .{});
        std.posix.connect(self.sock, &self.proxy_addr.any, self.proxy_addr.getOsSockLen()) catch |err| {
            std.debug.print("[SOCKS5-BLOCK-ERROR] connect() failed: {}\n", .{err});
            std.posix.close(self.sock);
            return error.ConnectionFailed;
        };

        std.debug.print("[SOCKS5-BLOCK] Connected to proxy!\n", .{});

        // Send greeting
        self.write_buf[0] = 0x05;
        self.write_buf[1] = 0x01;
        self.write_buf[2] = 0x00;

        _ = std.posix.write(self.sock, self.write_buf[0..3]) catch |err| {
            std.debug.print("[SOCKS5-BLOCK-ERROR] write() failed: {}\n", .{err});
            std.posix.close(self.sock);
            return error.SocketFailed;
        };
        std.debug.print("[SOCKS5-BLOCK] Sent greeting (3 bytes)\n", .{});

        // Read greeting ack
        _ = std.posix.read(self.sock, self.read_buf[0..2]) catch |err| {
            std.debug.print("[SOCKS5-BLOCK-ERROR] read() failed: {}\n", .{err});
            std.posix.close(self.sock);
            return error.SocketFailed;
        };
        std.debug.print("[SOCKS5-BLOCK] Received greeting ack: {x} {x}\n", .{ self.read_buf[0], self.read_buf[1] });

        if (self.read_buf[0] != 0x05 or self.read_buf[1] != 0x00) {
            std.debug.print("[SOCKS5-BLOCK-ERROR] Invalid greeting ack\n", .{});
            std.posix.close(self.sock);
            return error.InvalidData;
        }

        // Send CONNECT request
        self.write_buf[0] = 0x05;
        self.write_buf[1] = 0x01;
        self.write_buf[2] = 0x00;
        self.write_buf[3] = 0x01; // IPv4
        std.mem.writeInt(u32, self.write_buf[4..8], target_ip, .big);
        std.mem.writeInt(u16, self.write_buf[8..10], target_port, .big);

        _ = std.posix.write(self.sock, self.write_buf[0..10]) catch |err| {
            std.debug.print("[SOCKS5-BLOCK-ERROR] write() failed: {}\n", .{err});
            std.posix.close(self.sock);
            return error.SocketFailed;
        };
        std.debug.print("[SOCKS5-BLOCK] Sent CONNECT request (10 bytes)\n", .{});

        // Read CONNECT reply
        _ = std.posix.read(self.sock, self.read_buf[0..10]) catch |err| {
            std.debug.print("[SOCKS5-BLOCK-ERROR] read() failed: {}\n", .{err});
            std.posix.close(self.sock);
            return error.SocketFailed;
        };
        std.debug.print("[SOCKS5-BLOCK] Received CONNECT reply: {x} {x}\n", .{ self.read_buf[0], self.read_buf[1] });

        if (self.read_buf[0] != 0x05 or self.read_buf[1] != 0x00) {
            std.debug.print("[SOCKS5-BLOCK-ERROR] CONNECT failed (code={})\n", .{self.read_buf[1]});
            std.posix.close(self.sock);
            return error.ConnectionFailed;
        }

        std.debug.print("[SOCKS5-BLOCK] CONNECT SUCCESS!\n", .{});
        self.state = .Ready;
        std.debug.print("[SOCKS5-BLOCK] state set to Ready, fd={}\n", .{self.sock});

        // CRITICAL: Register socket with libxev for reading proxy responses
        std.debug.print("[SOCKS5-BLOCK] Setting up completion...\n", .{});
        self.completion = .{
            .op = .{
                .read = .{
                    .fd = self.sock,
                    .buffer = .{ .slice = &self.read_buf },
                },
            },
            .userdata = self,
            .callback = onProxyRead,
        };
        std.debug.print("[SOCKS5-BLOCK] Calling loop.add()...\n", .{});
        self.loop.add(&self.completion);
        std.debug.print("[SOCKS5-BLOCK] loop.add() returned\n", .{});

        // NOTE: Do NOT call on_tunnel_ready callback here!
        // The router's SYN handling code handles the SYN-ACK send after connectBlocking returns.
        // Calling the callback here would cause duplicate SYN-ACK (once from callback, once from router code).

        std.debug.print("[SOCKS5-BLOCK-EXIT] ============================================\n\n", .{});
    }

    /// Send data through the proxy (after connection is established)
    pub fn send(self: *Socks5Client, data: []const u8) Socks5Error!usize {
        if (self.state != .Ready) return error.NotReady;

        // Copy data to write buffer
        @memcpy(self.write_buf[0..data.len], data);

        self.completion = .{
            .op = .{
                .write = .{
                    .fd = self.sock,
                    .buffer = .{ .slice = self.write_buf[0..data.len] },
                },
            },
            .userdata = self,
            .callback = onWrite,
        };
        self.loop.add(&self.completion);

        return data.len;
    }

    /// Get current state
    pub fn getState(self: *Socks5Client) Socks5State {
        return self.state;
    }

    /// Check if connected and ready
    pub fn isReady(self: *Socks5Client) bool {
        return self.state == .Ready;
    }

    /// Close the connection
    pub fn close(self: *Socks5Client) void {
        if (self.sock >= 0) {
            std.posix.close(self.sock);
        }
        self.sock = -1; // Invalid socket
        self.state = .Disconnected;
        self.pending_data = null;
    }

    /// Check if socket has data available (non-blocking) and call on_data callback
    pub fn checkForResponse(self: *Socks5Client) Socks5Error!void {
        if (self.sock < 0) return error.NotConnected;
        if (self.state != .Ready) return error.NotReady;

        // Set non-blocking mode
        const flags = std.posix.fcntl(self.sock, std.posix.F.GETFL, 0) catch 0;
        _ = std.posix.fcntl(self.sock, std.posix.F.SETFL, flags | 0x4000) catch {};

        // Try to read
        const n = std.posix.read(self.sock, self.read_buf[0..1]) catch |err| {
            // Restore blocking mode
            _ = std.posix.fcntl(self.sock, std.posix.F.SETFL, flags) catch {};
            if (err == error.WouldBlock or err == error.Eagain) {
                return; // No data available
            }
            return error.SocketFailed;
        };

        // Restore blocking mode
        _ = std.posix.fcntl(self.sock, std.posix.F.SETFL, flags) catch {};

        if (n > 0) {
            std.debug.print("[SOCKS5] Manual read: {} bytes from proxy\n", .{n});
            // We got data! Need to read the rest
            var total_read = n;
            while (total_read < self.read_buf.len) {
                const slice = self.read_buf[total_read..];
                const more = std.posix.read(self.sock, slice) catch break;
                if (more == 0) break;
                total_read += more;
            }

            // Call on_data callback
            if (self.on_data) |cb| {
                std.debug.print("[SOCKS5] Calling on_data with {} bytes\n", .{total_read});
                cb(self.userdata, self.read_buf[0..total_read]);
            }
        }
    }
};

// ============ libxev Callbacks ============

/// Connect callback - initiates SOCKS5 handshake
fn onConnect(
    userdata: ?*anyopaque,
    loop: *xev.Loop,
    completion: *xev.Completion,
    result: xev.Result,
) xev.CallbackAction {
    _ = loop;
    _ = completion;

    const self: *Socks5Client = @ptrCast(@alignCast(userdata orelse return .disarm));

    std.debug.print("\n[SOCKS5] ============================================\n", .{});
    std.debug.print("[SOCKS5] onConnect callback at {}\n", .{std.time.nanoTimestamp()});
    std.debug.print("[SOCKS5] socket={} target={s}:{}\n", .{ self.sock, fmtIp(self.dst_ip), self.dst_port });
    std.debug.print("[SOCKS5] pending_data={}\n", .{self.pending_data != null});

    _ = result.connect catch |err| {
        std.debug.print("[SOCKS5-ERROR] Connect failed: {}\n", .{err});
        self.state = .Error;
        if (self.on_error) |cb| {
            cb(self.userdata, error.ConnectionFailed, self);
        }
        std.debug.print("[SOCKS5-STATE] Changed to .Error\n", .{});
        std.debug.print("[SOCKS5-EXIT] ============================================\n\n", .{});
        return .disarm;
    };

    std.debug.print("[SOCKS5] TCP connection to proxy established\n", .{});
    std.debug.print("[SOCKS5] Sending SOCKS5 greeting...\n", .{});

    // Send greeting: VER=5, NMETHODS=1, METHODS=[NO AUTH]
    self.state = .Greeting;
    std.debug.print("[SOCKS5-STATE] Changed to .Greeting\n", .{});

    self.write_buf[0] = 0x05; // SOCKS5 version
    self.write_buf[1] = 0x01; // Number of auth methods
    self.write_buf[2] = 0x00; // No authentication

    std.debug.print("[SOCKS5] Greeting: 05 01 00\n", .{});

    // Submit write for greeting
    self.completion = .{
        .op = .{
            .write = .{
                .fd = self.sock,
                .buffer = .{ .slice = self.write_buf[0..3] },
            },
        },
        .userdata = self,
        .callback = onGreetingWrite,
    };
    self.loop.add(&self.completion);

    std.debug.print("[SOCKS5] Write completion submitted\n", .{});
    std.debug.print("[SOCKS5-EXIT] ============================================\n\n", .{});

    return .disarm;
}

/// Greeting write callback - wait for greeting ack
fn onGreetingWrite(
    userdata: ?*anyopaque,
    loop: *xev.Loop,
    completion: *xev.Completion,
    result: xev.Result,
) xev.CallbackAction {
    _ = loop;
    _ = completion;

    const self: *Socks5Client = @ptrCast(@alignCast(userdata orelse return .disarm));

    std.debug.print("\n[SOCKS5] onGreetingWrite callback\n", .{});
    std.debug.print("[SOCKS5] Current state: {s}\n", .{@tagName(self.state)});

    _ = result.write catch |err| {
        std.debug.print("[SOCKS5-ERROR] Greeting write failed: {}\n", .{err});
        self.state = .Error;
        if (self.on_error) |cb| {
            cb(self.userdata, error.SocketFailed, self);
        }
        return .disarm;
    };

    std.debug.print("[SOCKS5] Greeting sent successfully (3 bytes)\n", .{});
    std.debug.print("[SOCKS5] Waiting for greeting acknowledgment...\n", .{});

    // Read greeting acknowledgment
    self.completion = .{
        .op = .{
            .read = .{
                .fd = self.sock,
                .buffer = .{ .slice = self.read_buf[0..2] },
            },
        },
        .userdata = self,
        .callback = onGreetingAck,
    };
    self.loop.add(&self.completion);

    std.debug.print("[SOCKS5] Read completion submitted\n", .{});

    return .disarm;
}

/// Greeting acknowledgment callback - check auth method
fn onGreetingAck(
    userdata: ?*anyopaque,
    loop: *xev.Loop,
    completion: *xev.Completion,
    result: xev.Result,
) xev.CallbackAction {
    _ = loop;
    _ = completion;

    const self: *Socks5Client = @ptrCast(@alignCast(userdata orelse return .disarm));

    std.debug.print("\n[SOCKS5] onGreetingAck callback\n", .{});
    std.debug.print("[SOCKS5] Current state: {s}\n", .{@tagName(self.state)});

    const n = result.read catch |err| {
        std.debug.print("[SOCKS5-ERROR] Greeting ack read failed: {}\n", .{err});
        self.state = .Error;
        if (self.on_error) |cb| {
            cb(self.userdata, error.InvalidData, self);
        }
        return .disarm;
    };

    if (n == 0) {
        std.debug.print("[SOCKS5-ERROR] Greeting ack: EOF (connection closed)\n", .{});
        self.state = .Closed;
        return .disarm;
    }

    std.debug.print("[SOCKS5] Received greeting ack: {x:0>2} {x:0>2} (n={})\n", .{ self.read_buf[0], self.read_buf[1], n });

    // Check response
    if (self.read_buf[0] != 0x05) {
        std.debug.print("[SOCKS5-ERROR] Invalid SOCKS version: expected 05, got {x:0>2}\n", .{self.read_buf[0]});
        self.state = .Error;
        if (self.on_error) |cb| {
            cb(self.userdata, error.InvalidVersion, self);
        }
        return .disarm;
    }

    if (self.read_buf[1] != 0x00) {
        std.debug.print("[SOCKS5-ERROR] Auth required but not supported (method={x:0>2})\n", .{self.read_buf[1]});
        self.state = .Error;
        if (self.on_error) |cb| {
            cb(self.userdata, error.AuthRequired, self);
        }
        return .disarm;
    }

    // Greeting accepted, send CONNECT request
    std.debug.print("[SOCKS5] Greeting accepted! No authentication required.\n", .{});
    self.state = .Request;
    std.debug.print("[SOCKS5-STATE] Changed to .Request\n", .{});

    // Build CONNECT request: VER=5, CMD=CONNECT, RSV=0, ATYP=IPv4, DST.ADDR, DST.PORT
    self.write_buf[0] = 0x05; // SOCKS5 version
    self.write_buf[1] = 0x01; // CONNECT command
    self.write_buf[2] = 0x00; // Reserved
    self.write_buf[3] = 0x01; // IPv4 address type

    // Destination IP (network byte order)
    std.mem.writeInt(u32, self.write_buf[4..8], self.dst_ip, .big);

    // Destination port (network byte order)
    std.mem.writeInt(u16, self.write_buf[8..10], self.dst_port, .big);

    std.debug.print("[SOCKS5] Sending CONNECT request:\n", .{});
    std.debug.print("[SOCKS5]   Target: {s}:{}\n", .{ fmtIp(self.dst_ip), self.dst_port });
    std.debug.print("[SOCKS5]   Request: 05 01 00 01 {x:0>2} {x:0>2} {x:0>2} {x:0>2} {x:0>2} {x:0>2}\n", .{ self.write_buf[4], self.write_buf[5], self.write_buf[6], self.write_buf[7], self.write_buf[8], self.write_buf[9] });

    // Submit write for CONNECT request
    self.completion = .{
        .op = .{
            .write = .{
                .fd = self.sock,
                .buffer = .{ .slice = self.write_buf[0..10] },
            },
        },
        .userdata = self,
        .callback = onRequestWrite,
    };
    self.loop.add(&self.completion);

    std.debug.print("[SOCKS5] CONNECT write completion submitted\n", .{});

    return .disarm;
}

/// CONNECT request write callback - wait for reply
fn onRequestWrite(
    userdata: ?*anyopaque,
    loop: *xev.Loop,
    completion: *xev.Completion,
    result: xev.Result,
) xev.CallbackAction {
    _ = loop;
    _ = completion;

    const self: *Socks5Client = @ptrCast(@alignCast(userdata orelse return .disarm));

    std.debug.print("\n[SOCKS5] onRequestWrite callback\n", .{});
    std.debug.print("[SOCKS5] Current state: {s}\n", .{@tagName(self.state)});

    _ = result.write catch |err| {
        std.debug.print("[SOCKS5-ERROR] CONNECT request write failed: {}\n", .{err});
        self.state = .Error;
        if (self.on_error) |cb| {
            cb(self.userdata, error.SocketFailed, self);
        }
        return .disarm;
    };

    std.debug.print("[SOCKS5] CONNECT request sent (10 bytes)\n", .{});
    std.debug.print("[SOCKS5] Waiting for CONNECT reply...\n", .{});

    // Read CONNECT reply
    self.completion = .{
        .op = .{
            .read = .{
                .fd = self.sock,
                .buffer = .{ .slice = self.read_buf[0..10] },
            },
        },
        .userdata = self,
        .callback = onRequestAck,
    };
    self.loop.add(&self.completion);

    std.debug.print("[SOCKS5] Read completion submitted\n", .{});

    return .disarm;
}

/// CONNECT reply callback - check if connection successful
fn onRequestAck(
    userdata: ?*anyopaque,
    loop: *xev.Loop,
    completion: *xev.Completion,
    result: xev.Result,
) xev.CallbackAction {
    _ = loop;
    _ = completion;

    const self: *Socks5Client = @ptrCast(@alignCast(userdata orelse return .disarm));

    std.debug.print("\n[SOCKS5] onRequestAck callback\n", .{});
    std.debug.print("[SOCKS5] Current state: {s}\n", .{@tagName(self.state)});
    std.debug.print("[SOCKS5] Target: {s}:{}\n", .{ fmtIp(self.dst_ip), self.dst_port });

    const n = result.read catch |err| {
        std.debug.print("[SOCKS5-ERROR] CONNECT reply read failed: {}\n", .{err});
        self.state = .Error;
        if (self.on_error) |cb| {
            cb(self.userdata, error.InvalidData, self);
        }
        return .disarm;
    };

    if (n == 0) {
        std.debug.print("[SOCKS5-ERROR] CONNECT reply: EOF (proxy closed connection)\n", .{});
        self.state = .Closed;
        return .disarm;
    }

    std.debug.print("[SOCKS5] Received CONNECT reply: {x:0>2} {x:0>2} (n={})\n", .{ self.read_buf[0], self.read_buf[1], n });

    // Check reply
    if (self.read_buf[0] != 0x05) {
        std.debug.print("[SOCKS5-ERROR] Invalid SOCKS version in reply: expected 05, got {x:0>2}\n", .{self.read_buf[0]});
        self.state = .Error;
        if (self.on_error) |cb| {
            cb(self.userdata, error.InvalidVersion, self);
        }
        return .disarm;
    }

    const reply_code = self.read_buf[1];
    if (reply_code != 0x00) {
        std.debug.print("[SOCKS5-ERROR] CONNECT failed! Reply code: {x:0>2}\n", .{reply_code});
        // Map error codes to human-readable messages
        const err_msg = switch (reply_code) {
            0x01 => "General SOCKS server failure",
            0x02 => "Connection not allowed by ruleset",
            0x03 => "Network unreachable",
            0x04 => "Host unreachable",
            0x05 => "Connection refused",
            0x06 => "TTL expired",
            0x07 => "Command not supported",
            0x08 => "Address type not supported",
            else => "Unknown error",
        };
        std.debug.print("[SOCKS5-ERROR]   {s}\n", .{err_msg});
        self.state = .Error;
        if (self.on_error) |cb| {
            cb(self.userdata, error.ConnectionFailed, self);
        }
        return .disarm;
    }

    // Connection successful!
    std.debug.print("[SOCKS5] CONNECT SUCCESS! Tunnel established to {s}:{}\n", .{ fmtIp(self.dst_ip), self.dst_port });
    std.debug.print("[SOCKS5] SOCKS5 tunnel ready!\n", .{});

    self.state = .Ready;
    std.debug.print("[SOCKS5-STATE] Changed to .Ready\n", .{});

    // Notify tunnel ready (for TCP handshake completion)
    if (self.on_tunnel_ready) |cb| {
        std.debug.print("[SOCKS5] Calling on_tunnel_ready callback...\n", .{});
        cb(self.userdata, self);
        std.debug.print("[SOCKS5] on_tunnel_ready callback returned\n", .{});
    } else {
        std.debug.print("[SOCKS5-WARN] No on_tunnel_ready callback set\n", .{});
    }

    // Send pending data if any
    if (self.pending_data) |data| {
        std.debug.print("[SOCKS5] Sending pending data ({} bytes)\n", .{data.len});
        @memcpy(self.write_buf[0..data.len], data);
        self.completion = .{
            .op = .{
                .write = .{
                    .fd = self.sock,
                    .buffer = .{ .slice = self.write_buf[0..data.len] },
                },
            },
            .userdata = self,
            .callback = onDataWrite,
        };
        self.loop.add(&self.completion);
        self.pending_data = null;
        std.debug.print("[SOCKS5] Pending data write submitted\n", .{});
    }

    // Notify ready
    if (self.on_ready) |cb| {
        std.debug.print("[SOCKS5] Calling on_ready callback...\n", .{});
        cb(self.userdata, self);
        std.debug.print("[SOCKS5] on_ready callback returned\n", .{});
    }

    // Start reading responses from proxy
    self.completion = .{
        .op = .{
            .read = .{
                .fd = self.sock,
                .buffer = .{ .slice = &self.read_buf },
            },
        },
        .userdata = self,
        .callback = onProxyRead,
    };
    self.loop.add(&self.completion);

    std.debug.print("[SOCKS5] Proxy read loop started\n", .{});
    std.debug.print("[SOCKS5-EXIT] ============================================\n\n", .{});

    return .disarm;
}

/// Data write callback - sent pending/new data
fn onWrite(
    userdata: ?*anyopaque,
    loop: *xev.Loop,
    completion: *xev.Completion,
    result: xev.Result,
) xev.CallbackAction {
    _ = loop;
    _ = completion;

    const self: *Socks5Client = @ptrCast(@alignCast(userdata orelse return .disarm));

    std.debug.print("\n[SOCKS5] onWrite callback\n", .{});

    _ = result.write catch |err| {
        std.debug.print("[SOCKS5-ERROR] Data write failed: {}\n", .{err});
        self.state = .Error;
        if (self.on_error) |cb| {
            cb(self.userdata, error.SocketFailed, self);
        }
        return .disarm;
    };

    std.debug.print("[SOCKS5] Data sent successfully\n", .{});

    // Continue reading responses
    self.completion = .{
        .op = .{
            .read = .{
                .fd = self.sock,
                .buffer = .{ .slice = &self.read_buf },
            },
        },
        .userdata = self,
        .callback = onProxyRead,
    };
    self.loop.add(&self.completion);

    return .disarm;
}

/// Data write callback for pending data
fn onDataWrite(
    userdata: ?*anyopaque,
    loop: *xev.Loop,
    completion: *xev.Completion,
    result: xev.Result,
) xev.CallbackAction {
    _ = loop;
    _ = completion;

    const self: *Socks5Client = @ptrCast(@alignCast(userdata orelse return .disarm));

    std.debug.print("\n[SOCKS5] onDataWrite callback\n", .{});

    _ = result.write catch |err| {
        std.debug.print("[SOCKS5-ERROR] Pending data write failed: {}\n", .{err});
        self.state = .Error;
        if (self.on_error) |cb| {
            cb(self.userdata, error.SocketFailed, self);
        }
        return .disarm;
    };

    std.debug.print("[SOCKS5] Pending data sent successfully\n", .{});

    // Continue reading responses
    self.completion = .{
        .op = .{
            .read = .{
                .fd = self.sock,
                .buffer = .{ .slice = &self.read_buf },
            },
        },
        .userdata = self,
        .callback = onProxyRead,
    };
    self.loop.add(&self.completion);

    return .disarm;
}

/// Proxy read callback - received data from target server
fn onProxyRead(
    userdata: ?*anyopaque,
    loop: *xev.Loop,
    completion: *xev.Completion,
    result: xev.Result,
) xev.CallbackAction {
    _ = loop;
    _ = completion;

    const self: *Socks5Client = @ptrCast(@alignCast(userdata orelse return .disarm));

    std.debug.print("\n[SOCKS5] onProxyRead callback\n", .{});
    std.debug.print("[SOCKS5] Current state: {s}\n", .{@tagName(self.state)});

    const n = result.read catch |err| {
        std.debug.print("[SOCKS5-ERROR] Proxy read failed: {}\n", .{err});
        self.state = .Error;
        if (self.on_error) |cb| {
            cb(self.userdata, error.SocketFailed, self);
        }
        return .disarm;
    };

    if (n == 0) {
        std.debug.print("[SOCKS5-WARN] Proxy closed connection (EOF)\n", .{});
        self.state = .Closed;
        return .disarm;
    }

    std.debug.print("[SOCKS5] Received {} bytes from proxy (target: {s}:{})\n", .{ n, fmtIp(self.dst_ip), self.dst_port });

    // Forward data to callback
    if (self.on_data) |cb| {
        std.debug.print("[SOCKS5] Calling on_data callback...\n", .{});
        cb(self.userdata, self.read_buf[0..n], self);
        std.debug.print("[SOCKS5] on_data callback returned\n", .{});
    } else {
        std.debug.print("[SOCKS5-WARN] No on_data callback set, data dropped\n", .{});
    }

    // Continue reading
    self.completion = .{
        .op = .{
            .read = .{
                .fd = self.sock,
                .buffer = .{ .slice = &self.read_buf },
            },
        },
        .userdata = self,
        .callback = onProxyRead,
    };
    self.loop.add(&self.completion);

    std.debug.print("[SOCKS5] Continue reading...\n", .{});

    return .disarm;
}
