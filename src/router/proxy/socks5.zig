//! socks5.zig - SOCKS5 Proxy Client with libxev
//!
//! Implements a complete SOCKS5 proxy client with async I/O support.
//! Uses libxev's completion callbacks for non-blocking I/O.
//!
//! Usage:
//!   1. Create a Socks5Client with create()
//!   2. Call connect() to establish connection to SOCKS5 proxy
//!   3. Use send() and recv() to forward data through the proxy

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
pub const DataCallback = *const fn (userdata: ?*anyopaque, data: []const u8) void;

/// Callback when SOCKS5 tunnel is established
pub const TunnelReadyCallback = *const fn (userdata: ?*anyopaque) void;

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
        on_ready: ?*const fn (?*anyopaque) void,
        on_error: ?*const fn (?*anyopaque, Socks5Error) void,
    ) void {
        self.userdata = userdata;
        self.on_data = on_data;
        self.on_tunnel_ready = on_tunnel_ready;
        self.on_ready = on_ready;
        self.on_error = on_error;
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
        std.debug.print("[SOCKS5] target_ip={s} target_port={}\n", .{fmtIp(target_ip), target_port});
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
        std.debug.print("[SOCKS5] proxy_addr family={} port={}\n", .{self.proxy_addr.any.family, self.proxy_addr.getPort()});

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
        std.debug.print("[SOCKS5-BLOCK] target_ip={s} target_port={}\n", .{fmtIp(target_ip), target_port});

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
    std.debug.print("[SOCKS5] socket={} target={s}:{}\n", .{self.sock, fmtIp(self.dst_ip), self.dst_port});
    std.debug.print("[SOCKS5] pending_data={}\n", .{self.pending_data != null});

    _ = result.connect catch |err| {
        std.debug.print("[SOCKS5-ERROR] Connect failed: {}\n", .{err});
        self.state = .Error;
        if (self.on_error) |cb| {
            cb(self.userdata, error.ConnectionFailed);
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

    self.write_buf[0] = 0x05;  // SOCKS5 version
    self.write_buf[1] = 0x01;  // Number of auth methods
    self.write_buf[2] = 0x00;  // No authentication

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
            cb(self.userdata, error.SocketFailed);
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
            cb(self.userdata, error.InvalidData);
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
            cb(self.userdata, error.InvalidVersion);
        }
        return .disarm;
    }

    if (self.read_buf[1] != 0x00) {
        std.debug.print("[SOCKS5-ERROR] Auth required but not supported (method={x:0>2})\n", .{self.read_buf[1]});
        self.state = .Error;
        if (self.on_error) |cb| {
            cb(self.userdata, error.AuthRequired);
        }
        return .disarm;
    }

    // Greeting accepted, send CONNECT request
    std.debug.print("[SOCKS5] Greeting accepted! No authentication required.\n", .{});
    self.state = .Request;
    std.debug.print("[SOCKS5-STATE] Changed to .Request\n", .{});

    // Build CONNECT request: VER=5, CMD=CONNECT, RSV=0, ATYP=IPv4, DST.ADDR, DST.PORT
    self.write_buf[0] = 0x05;  // SOCKS5 version
    self.write_buf[1] = 0x01;  // CONNECT command
    self.write_buf[2] = 0x00;  // Reserved
    self.write_buf[3] = 0x01;  // IPv4 address type

    // Destination IP (network byte order)
    std.mem.writeInt(u32, self.write_buf[4..8], self.dst_ip, .big);

    // Destination port (network byte order)
    std.mem.writeInt(u16, self.write_buf[8..10], self.dst_port, .big);

    std.debug.print("[SOCKS5] Sending CONNECT request:\n", .{});
    std.debug.print("[SOCKS5]   Target: {s}:{}\n", .{fmtIp(self.dst_ip), self.dst_port});
    std.debug.print("[SOCKS5]   Request: 05 01 00 01 {x:0>2} {x:0>2} {x:0>2} {x:0>2} {x:0>2} {x:0>2}\n", .{
        self.write_buf[4], self.write_buf[5], self.write_buf[6], self.write_buf[7],
        self.write_buf[8], self.write_buf[9] });

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
            cb(self.userdata, error.SocketFailed);
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
    std.debug.print("[SOCKS5] Target: {s}:{}\n", .{fmtIp(self.dst_ip), self.dst_port});

    const n = result.read catch |err| {
        std.debug.print("[SOCKS5-ERROR] CONNECT reply read failed: {}\n", .{err});
        self.state = .Error;
        if (self.on_error) |cb| {
            cb(self.userdata, error.InvalidData);
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
            cb(self.userdata, error.InvalidVersion);
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
            cb(self.userdata, error.ConnectionFailed);
        }
        return .disarm;
    }

    // Connection successful!
    std.debug.print("[SOCKS5] CONNECT SUCCESS! Tunnel established to {s}:{}\n", .{
        fmtIp(self.dst_ip), self.dst_port });
    std.debug.print("[SOCKS5] SOCKS5 tunnel ready!\n", .{});

    self.state = .Ready;
    std.debug.print("[SOCKS5-STATE] Changed to .Ready\n", .{});

    // Notify tunnel ready (for TCP handshake completion)
    if (self.on_tunnel_ready) |cb| {
        std.debug.print("[SOCKS5] Calling on_tunnel_ready callback...\n", .{});
        cb(self.userdata);
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
        cb(self.userdata);
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
            cb(self.userdata, error.SocketFailed);
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
            cb(self.userdata, error.SocketFailed);
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
            cb(self.userdata, error.SocketFailed);
        }
        return .disarm;
    };

    if (n == 0) {
        std.debug.print("[SOCKS5-WARN] Proxy closed connection (EOF)\n", .{});
        self.state = .Closed;
        return .disarm;
    }

    std.debug.print("[SOCKS5] Received {} bytes from proxy (target: {s}:{})\n", .{n, fmtIp(self.dst_ip), self.dst_port});

    // Forward data to callback
    if (self.on_data) |cb| {
        std.debug.print("[SOCKS5] Calling on_data callback...\n", .{});
        cb(self.userdata, self.read_buf[0..n]);
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
