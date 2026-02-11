//! socks5.zig - SOCKS5 Proxy Client with libxev
//!
//! Implements a complete SOCKS5 proxy client with async I/O support.
//! This module handles the SOCKS5 handshake (greeting, connect request)
//! and provides send/recv operations for data forwarding.
//!
//! Usage:
//!   1. Create a Socks5Client with create()
//!   2. Call connect() to establish connection to SOCKS5 proxy
//!   3. Use send() and recv() to forward data through the proxy

const std = @import("std");
const xev = @import("xev");

// Socket constants (define locally for cross-platform compatibility)
const AF_INET = 2;   // IPv4
const SOCK_STREAM = 1;
const SOCK_DGRAM = 2;
const O_NONBLOCK = 0x4000;

/// SOCKS5 connection state
pub const Socks5State = enum(u8) {
    /// Initial state, need to connect
    Disconnected = 0,
    /// Connecting to proxy
    Connecting = 1,
    /// Sent greeting, waiting for ack
    Greeting = 2,
    /// Sent connect request, waiting for ack
    Connect = 3,
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
/// Called when data is received from the SOCKS5 proxy
const DataCallback = *const fn (userdata: ?*anyopaque, data: []const u8) void;

/// Context for SOCKS5 client callbacks
const Callbacks = struct {
    on_data: ?DataCallback = null,
    on_ready: ?*const fn (userdata: ?*anyopaque) void = null,
    on_error: ?*const fn (userdata: ?*anyopaque, err: Socks5Error) void = null,
};

/// SOCKS5 proxy connection state and buffers
pub const Socks5Client = struct {
    /// libxev event loop
    loop: *xev.Loop,

    /// libxev completion for async operations
    completion: xev.Completion,

    /// Socket to SOCKS5 proxy
    sock: ?std.posix.socket_t = null,

    /// Connection state
    state: Socks5State = .Disconnected,

    /// Proxy server address
    proxy_addr: std.net.Address,

    /// Target server address (for CONNECT)
    dst_ip: u32 = 0,
    dst_port: u16 = 0,

    /// Read buffer for receiving from proxy
    read_buf: [65536]u8 = undefined,
    read_offset: usize = 0,

    /// Write buffer for sending to proxy
    write_buf: [65536]u8 = undefined,
    write_offset: usize = 0,

    /// Pending payload to send after connection established
    pending_data: ?[]const u8 = null,

    /// User-provided context for callbacks
    userdata: ?*anyopaque = null,

    /// Callbacks
    callbacks: Callbacks = .{},

    /// Create a new SOCKS5 client
    pub fn create(
        allocator: std.mem.Allocator,
        loop: *xev.Loop,
        proxy_addr: std.net.Address,
    ) !*Socks5Client {
        const client = try allocator.create(Socks5Client);
        client.* = Socks5Client{
            .loop = loop,
            .completion = undefined,
            .proxy_addr = proxy_addr,
        };
        return client;
    }

    /// Destroy a SOCKS5 client
    pub fn destroy(self: *Socks5Client, allocator: std.mem.Allocator) void {
        if (self.sock) |s| {
            std.posix.close(s);
        }
        allocator.destroy(self);
    }

    /// Set callbacks for client events
    pub fn setCallbacks(
        self: *Socks5Client,
        userdata: ?*anyopaque,
        on_data: ?DataCallback,
        on_ready: ?*const fn (?*anyopaque) void,
        on_error: ?*const fn (?*anyopaque, Socks5Error) void,
    ) void {
        self.userdata = userdata;
        if (on_data) |cb| self.callbacks.on_data = cb;
        if (on_ready) |cb| self.callbacks.on_ready = cb;
        if (on_error) |cb| self.callbacks.on_error = cb;
    }

    /// Connect to SOCKS5 proxy and establish tunnel
    pub fn connect(self: *Socks5Client, target_ip: u32, target_port: u16, data: ?[]const u8) Socks5Error!void {
        // Store target info
        self.dst_ip = target_ip;
        self.dst_port = target_port;
        self.pending_data = data;

        // Create socket
        self.sock = std.posix.socket(AF_INET, SOCK_STREAM, 0) catch {
            return error.SocketFailed;
        };

        // Non-blocking
        const flags = std.posix.fcntl(self.sock.?, std.posix.F.GETFL, 0) catch {
            return error.SocketFailed;
        };
        _ = std.posix.fcntl(self.sock.?, std.posix.F.SETFL, flags | O_NONBLOCK) catch {};

        // Connect to proxy
        const result = std.posix.connect(self.sock.?, &self.proxy_addr.any, @sizeOf(std.posix.sockaddr));

        if (result) {
            // Connected immediately
            self.state = .Greeting;
            try self.sendGreeting();
        } else |err| {
            if (err != std.posix.ConnectError.WouldBlock) {
                return error.ConnectionFailed;
            }
            // WouldBlock - wait for completion
            self.state = .Connecting;

            self.completion = .{
                .op = .{
                    .connect = .{
                        .socket = self.sock.?,
                        .addr = self.proxy_addr,
                    },
                },
                .userdata = self,
                .callback = onConnect,
            };
            self.loop.add(&self.completion);
        }
    }

    /// Send data through the proxy (after connection is established)
    pub fn send(self: *Socks5Client, data: []const u8) Socks5Error!usize {
        const sock = self.sock orelse return error.NotConnected;
        if (self.state != .Ready) return error.NotReady;

        return std.posix.send(sock, data, 0) catch error.SocketFailed;
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
        if (self.sock) |s| {
            std.posix.close(s);
            self.sock = null;
        }
        self.state = .Closed;
    }

    // ============ Private Methods ============

    /// Send SOCKS5 greeting
    fn sendGreeting(self: *Socks5Client) Socks5Error!void {
        const sock = self.sock orelse return error.NotConnected;

        // Build greeting: VER=5, NMETHODS=1, METHODS=[NO AUTH]
        var greeting: [3]u8 = undefined;
        greeting[0] = 0x05; // SOCKS5 version
        greeting[1] = 1;     // Number of auth methods
        greeting[2] = 0x00; // No authentication

        const sent = std.posix.send(sock, &greeting, 0) catch {
            return error.SocketFailed;
        };
        if (sent != 3) return error.SocketFailed;

        self.state = .Greeting;
        self.read_offset = 0;

        // Wait for greeting ack
        self.completion = .{
            .op = .{
                .read = .{
                    .fd = sock,
                    .buffer = .{ .slice = &self.read_buf },
                },
            },
            .userdata = self,
            .callback = onGreetingAck,
        };
        self.loop.add(&self.completion);
    }

    /// Send CONNECT request
    fn sendConnectRequest(self: *Socks5Client) Socks5Error!void {
        const sock = self.sock orelse return error.NotConnected;

        // Build connect request: VER=5, CMD=CONNECT, RSV=0, ATYP=IPv4, DST.ADDR, DST.PORT
        var request: [10]u8 = undefined;
        request[0] = 0x05; // SOCKS5 version
        request[1] = 0x01; // CONNECT command
        request[2] = 0x00; // Reserved
        request[3] = 0x01; // IPv4 address type

        // Destination IP (network byte order)
        std.mem.writeInt(u32, request[4..8], self.dst_ip, .big);

        // Destination port (network byte order)
        std.mem.writeInt(u16, request[8..10], self.dst_port, .big);

        const sent = std.posix.send(sock, &request, 0) catch {
            return error.SocketFailed;
        };
        if (sent != 10) return error.SocketFailed;

        self.state = .Connect;
        self.read_offset = 0;

        // Wait for connect ack
        self.completion = .{
            .op = .{
                .read = .{
                    .fd = sock,
                    .buffer = .{ .slice = &self.read_buf },
                },
            },
            .userdata = self,
            .callback = onConnectAck,
        };
        self.loop.add(&self.completion);
    }

    /// Start reading data from proxy
    fn startRead(self: *Socks5Client) void {
        const sock = self.sock orelse return;

        self.completion = .{
            .op = .{
                .read = .{
                    .fd = sock,
                    .buffer = .{ .slice = &self.read_buf },
                },
            },
            .userdata = self,
            .callback = onReadable,
        };
        self.loop.add(&self.completion);
    }

    /// Call error callback
    fn notifyError(self: *Socks5Client, err: Socks5Error) void {
        if (self.callbacks.on_error) |cb| {
            cb(self.userdata, err);
        }
    }

    /// Call ready callback
    fn notifyReady(self: *Socks5Client) void {
        if (self.callbacks.on_ready) |cb| {
            cb(self.userdata);
        }
    }

    /// Call data callback
    fn notifyData(self: *Socks5Client, data: []const u8) void {
        if (self.callbacks.on_data) |cb| {
            cb(self.userdata, data);
        }
    }
};

// ============ libxev Callbacks ============

fn onConnect(
    userdata: ?*anyopaque,
    loop: *xev.Loop,
    completion: *xev.Completion,
    result: xev.Result,
) xev.CallbackAction {
    _ = loop;
    _ = completion;

    const self = @as(*Socks5Client, @ptrCast(@alignCast(userdata orelse return .disarm)));

    _ = result.connect catch {
        self.state = .Error;
        self.notifyError(error.ConnectionFailed);
        return .disarm;
    };

    // Connected, send greeting
    self.state = .Greeting;
    self.sendGreeting() catch {
        self.state = .Error;
        self.notifyError(error.SocketFailed);
    };

    return .disarm;
}

fn onGreetingAck(
    userdata: ?*anyopaque,
    loop: *xev.Loop,
    completion: *xev.Completion,
    result: xev.Result,
) xev.CallbackAction {
    _ = loop;
    _ = completion;

    const self = @as(*Socks5Client, @ptrCast(@alignCast(userdata orelse return .disarm)));

    const n = result.read catch {
        self.state = .Error;
        self.notifyError(error.SocketFailed);
        return .disarm;
    };

    if (n == 0) {
        self.state = .Error;
        self.notifyError(error.ConnectionFailed);
        return .disarm;
    }

    // Parse greeting acknowledgment
    if (self.read_buf[0] != 0x05) {
        self.state = .Error;
        self.notifyError(error.InvalidVersion);
        return .disarm;
    }

    if (self.read_buf[1] != 0x00) {
        self.state = .Error;
        self.notifyError(error.AuthRequired);
        return .disarm;
    }

    // Greeting accepted, send connect request
    self.state = .Connect;
    self.sendConnectRequest() catch {
        self.state = .Error;
        self.notifyError(error.SocketFailed);
    };

    return .disarm;
}

fn onConnectAck(
    userdata: ?*anyopaque,
    loop: *xev.Loop,
    completion: *xev.Completion,
    result: xev.Result,
) xev.CallbackAction {
    _ = loop;
    _ = completion;

    const self = @as(*Socks5Client, @ptrCast(@alignCast(userdata orelse return .disarm)));

    const n = result.read catch {
        self.state = .Error;
        self.notifyError(error.SocketFailed);
        return .disarm;
    };

    if (n == 0) {
        self.state = .Error;
        self.notifyError(error.ConnectionFailed);
        return .disarm;
    }

    // Parse connect reply
    if (self.read_buf[0] != 0x05) {
        self.state = .Error;
        self.notifyError(error.InvalidVersion);
        return .disarm;
    }

    if (self.read_buf[1] != 0x00) {
        self.state = .Error;
        self.notifyError(error.ConnectionFailed);
        return .disarm;
    }

    // Connection successful!
    self.state = .Ready;

    // Send pending data if any
    if (self.pending_data) |data| {
        _ = self.send(data) catch {};
        self.pending_data = null;
    }

    // Notify ready
    self.notifyReady();

    // Start reading responses
    self.startRead();

    return .disarm;
}

fn onReadable(
    userdata: ?*anyopaque,
    loop: *xev.Loop,
    completion: *xev.Completion,
    result: xev.Result,
) xev.CallbackAction {
    _ = loop;
    _ = completion;

    const self = @as(*Socks5Client, @ptrCast(@alignCast(userdata orelse return .disarm)));

    const n = result.read catch {
        self.state = .Error;
        self.notifyError(error.SocketFailed);
        return .disarm;
    };

    if (n == 0) {
        self.state = .Closed;
        return .disarm;
    }

    // Notify data to callback
    self.notifyData(self.read_buf[0..n]);

    // Continue reading
    self.startRead();

    return .disarm;
}

// ============ Protocol Helper Functions ============

/// Build SOCKS5 greeting message
pub fn buildGreeting(buf: []u8) usize {
    if (buf.len < 3) return 0;

    buf[0] = 0x05;  // SOCKS5 version
    buf[1] = 1;      // Number of auth methods
    buf[2] = 0x00;   // No authentication

    return 3;
}

/// Parse SOCKS5 greeting acknowledgment
pub fn parseGreetingAck(data: []const u8) Socks5Error!void {
    if (data.len < 2) return error.InvalidData;
    if (data[0] != 0x05) return error.InvalidVersion;
    if (data[1] == 0xFF) return error.AuthRequired;
}

/// Build SOCKS5 connect request
/// dst_ip: destination IP in network byte order
/// dst_port: destination port in host byte order (will be converted)
pub fn buildConnectRequest(buf: []u8, dst_ip: u32, dst_port: u16) usize {
    if (buf.len < 10) return 0;

    buf[0] = 0x05;  // SOCKS5 version
    buf[1] = 0x01;  // CONNECT command
    buf[2] = 0x00;  // Reserved

    // IPv4 address type
    buf[3] = 0x01;

    // Destination IP (network byte order)
    std.mem.writeInt(u32, buf[4..8], dst_ip, .big);

    // Destination port (network byte order)
    std.mem.writeInt(u16, buf[8..10], dst_port, .big);

    return 10;
}

/// Parse SOCKS5 connect reply
pub fn parseConnectReply(data: []const u8) Socks5Error!void {
    if (data.len < 10) return error.InvalidData;
    if (data[0] != 0x05) return error.InvalidVersion;
    if (data[1] != 0x00) return error.ConnectionFailed;
}

/// Build SOCKS5 username/password authentication request
pub fn buildUsernameAuth(buf: []u8, username: []const u8, password: []const u8) usize {
    const header_len = 2; // Version + username_length
    const min_size = header_len + username.len + 1 + password.len;

    if (buf.len < min_size) return 0;

    buf[0] = 0x01;  // Version 1
    buf[1] = @as(u8, @intCast(username.len));

    // Username
    @memcpy(buf[2..][0..username.len], username);

    // Password length
    buf[2 + username.len] = @as(u8, @intCast(password.len));

    // Password
    @memcpy(buf[3 + username.len..][0..password.len], password);

    return min_size;
}

/// Parse username/password authentication response
pub fn parseUsernameAuthResponse(data: []const u8) Socks5Error!void {
    if (data.len < 2) return error.InvalidData;
    if (data[0] != 0x01) return error.InvalidVersion;
    if (data[1] != 0x00) return error.AuthRequired;
}

/// Build SOCKS5 UDP ASSOCIATE request
pub fn buildUdpAssociate(buf: []u8, dst_ip: u32, dst_port: u16) usize {
    if (buf.len < 10) return 0;

    buf[0] = 0x05;  // SOCKS5 version
    buf[1] = 0x03;  // UDP ASSOCIATE command
    buf[2] = 0x00;  // Reserved

    // IPv4 address type
    buf[3] = 0x01;

    // Destination IP (network byte order)
    std.mem.writeInt(u32, buf[4..8], dst_ip, .big);

    // Destination port (network byte order)
    std.mem.writeInt(u16, buf[8..10], dst_port, .big);

    return 10;
}

/// Parse SOCKS5 UDP ASSOCIATE reply
pub fn parseUdpAssociateReply(data: []const u8) Socks5Error!struct { ip: u32, port: u16 } {
    if (data.len < 10) return error.InvalidData;
    if (data[0] != 0x05) return error.InvalidVersion;
    if (data[1] != 0x00) return error.ConnectionFailed;

    const ip = std.mem.readInt(u32, data[4..8], .big);
    const port = std.mem.readInt(u16, data[8..10], .big);

    return .{ .ip = ip, .port = port };
}
