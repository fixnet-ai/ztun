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
        // Store target info
        self.dst_ip = target_ip;
        self.dst_port = target_port;
        self.pending_data = data;
        self.state = .Connecting;

        // Create socket with NONBLOCK
        self.sock = std.posix.socket(
            self.proxy_addr.any.family,
            std.posix.SOCK.STREAM | std.posix.SOCK.NONBLOCK,
            0,
        ) catch {
            return error.SocketFailed;
        };

        // Start async connect
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

    _ = result.connect catch |err| {
        std.debug.print("[SOCKS5] Connect failed: {}\n", .{err});
        self.state = .Error;
        return .disarm;
    };

    std.debug.print("[SOCKS5] Connected to proxy, sending greeting\n", .{});

    // Send greeting: VER=5, NMETHODS=1, METHODS=[NO AUTH]
    self.state = .Greeting;
    self.write_buf[0] = 0x05;  // SOCKS5 version
    self.write_buf[1] = 0x01;  // Number of auth methods
    self.write_buf[2] = 0x00;  // No authentication

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

    _ = result.write catch |err| {
        std.debug.print("[SOCKS5] Greeting write failed: {}\n", .{err});
        self.state = .Error;
        return .disarm;
    };

    std.debug.print("[SOCKS5] Greeting sent, waiting for ack\n", .{});

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

    const n = result.read catch |err| {
        std.debug.print("[SOCKS5] Greeting ack read failed: {}\n", .{err});
        self.state = .Error;
        return .disarm;
    };

    if (n == 0) {
        std.debug.print("[SOCKS5] Greeting ack: EOF\n", .{});
        self.state = .Error;
        return .disarm;
    }

    std.debug.print("[SOCKS5] Greeting ack: {x} {x}\n", .{ self.read_buf[0], self.read_buf[1] });

    // Check response
    if (self.read_buf[0] != 0x05) {
        std.debug.print("[SOCKS5] Invalid version in greeting ack\n", .{});
        self.state = .Error;
        return .disarm;
    }

    if (self.read_buf[1] != 0x00) {
        std.debug.print("[SOCKS5] Auth required (not supported)\n", .{});
        self.state = .Error;
        return .disarm;
    }

    // Greeting accepted, send CONNECT request
    std.debug.print("[SOCKS5] Greeting accepted, sending CONNECT request\n", .{});
    self.state = .Request;

    // Build CONNECT request: VER=5, CMD=CONNECT, RSV=0, ATYP=IPv4, DST.ADDR, DST.PORT
    self.write_buf[0] = 0x05;  // SOCKS5 version
    self.write_buf[1] = 0x01;  // CONNECT command
    self.write_buf[2] = 0x00;  // Reserved
    self.write_buf[3] = 0x01;  // IPv4 address type

    // Destination IP (network byte order)
    std.mem.writeInt(u32, self.write_buf[4..8], self.dst_ip, .big);

    // Destination port (network byte order)
    std.mem.writeInt(u16, self.write_buf[8..10], self.dst_port, .big);

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

    _ = result.write catch |err| {
        std.debug.print("[SOCKS5] CONNECT request write failed: {}\n", .{err});
        self.state = .Error;
        return .disarm;
    };

    std.debug.print("[SOCKS5] CONNECT request sent, waiting for reply\n", .{});

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

    const n = result.read catch |err| {
        std.debug.print("[SOCKS5] CONNECT reply read failed: {}\n", .{err});
        self.state = .Error;
        return .disarm;
    };

    if (n == 0) {
        std.debug.print("[SOCKS5] CONNECT reply: EOF\n", .{});
        self.state = .Error;
        return .disarm;
    }

    std.debug.print("[SOCKS5] CONNECT reply: {x} {x}\n", .{ self.read_buf[0], self.read_buf[1] });

    // Check reply
    if (self.read_buf[0] != 0x05) {
        std.debug.print("[SOCKS5] Invalid version in CONNECT reply\n", .{});
        self.state = .Error;
        return .disarm;
    }

    if (self.read_buf[1] != 0x00) {
        std.debug.print("[SOCKS5] CONNECT failed (error code={x})\n", .{self.read_buf[1]});
        self.state = .Error;
        return .disarm;
    }

    // Connection successful!
    std.debug.print("[SOCKS5] Tunnel established to {s}:{}\n", .{
        fmtIp(self.dst_ip), self.dst_port });

    self.state = .Ready;

    // Notify tunnel ready (for TCP handshake completion)
    if (self.on_tunnel_ready) |cb| {
        cb(self.userdata);
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
    }

    // Notify ready
    if (self.on_ready) |cb| {
        cb(self.userdata);
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

    _ = result.write catch |err| {
        std.debug.print("[SOCKS5] Data write failed: {}\n", .{err});
        self.state = .Error;
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

    _ = result.write catch |err| {
        std.debug.print("[SOCKS5] Pending data write failed: {}\n", .{err});
        self.state = .Error;
        return .disarm;
    };

    std.debug.print("[SOCKS5] Pending data sent\n", .{});

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

    const n = result.read catch |err| {
        std.debug.print("[SOCKS5] Proxy read failed: {}\n", .{err});
        self.state = .Error;
        return .disarm;
    };

    if (n == 0) {
        std.debug.print("[SOCKS5] Proxy closed connection\n", .{});
        self.state = .Closed;
        return .disarm;
    }

    std.debug.print("[SOCKS5] Received {} bytes from proxy\n", .{n});

    // Forward data to callback
    if (self.on_data) |cb| {
        cb(self.userdata, self.read_buf[0..n]);
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

    return .disarm;
}
