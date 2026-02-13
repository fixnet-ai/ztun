//! http.zig - HTTP CONNECT Proxy Client
//!
//! Implements HTTP CONNECT tunneling for HTTPS proxy support.
//!
//! Usage:
//!   1. Create HttpClient with create()
//!   2. Call connect() to establish tunnel to proxy
//!   3. Use send() and recv() to forward data through the tunnel

const std = @import("std");
const xev = @import("xev");

// HTTP errors
pub const HttpError = error{
    ConnectionFailed,
    SocketFailed,
    InvalidData,
    NotSupported,
    NotConnected,
    Timeout,
};

/// HTTP response status codes
pub const StatusCode = enum(u16) {
    Continue = 100,
    Ok = 200,
    Created = 201,
    Accepted = 202,
    NonAuthoritative = 203,
    NoContent = 204,
    MovedPermanently = 301,
    Found = 302,
    SeeOther = 303,
    NotModified = 304,
    BadRequest = 400,
    Unauthorized = 401,
    Forbidden = 403,
    NotFound = 404,
    MethodNotAllowed = 405,
    ProxyAuthenticationRequired = 407,
    InternalServerError = 500,
    NotImplemented = 501,
    BadGateway = 502,
    ServiceUnavailable = 503,
};

/// Client state
pub const HttpState = enum(u8) {
    Disconnected = 0,
    Connecting = 1,
    Connected = 2,
    Ready = 3,
    Error = 4,
    Closed = 5,
};

/// Callback for tunnel established
pub const TunnelReadyCallback = *const fn (userdata: ?*anyopaque, client: *HttpClient) void;

/// HTTP CONNECT client
pub const HttpClient = struct {
    /// libxev event loop
    loop: *xev.Loop,

    /// Socket to proxy
    sock: std.posix.socket_t = undefined,

    /// Proxy address
    proxy_addr: std.net.Address,

    /// Target address (for CONNECT)
    target_addr: std.net.Address,

    /// Completion for async operations
    completion: xev.Completion = .{},

    /// Connection state
    state: HttpState = .Disconnected,

    /// Response buffer
    read_buf: [4096]u8 = undefined,
    write_buf: [4096]u8 = undefined,

    /// Bytes read in current operation
    bytes_read: usize = 0,

    /// User-provided context
    userdata: ?*anyopaque = null,

    /// Callbacks
    on_tunnel_ready: ?TunnelReadyCallback = null,
    on_data: ?*const fn (userdata: ?*anyopaque, data: []const u8) void = null,
    on_error: ?*const fn (userdata: ?*anyopaque, err: HttpError) void = null,

    /// Create a new HTTP client
    pub fn create(
        allocator: std.mem.Allocator,
        loop: *xev.Loop,
        proxy_addr: std.net.Address,
        target_addr: std.net.Address,
    ) !*HttpClient {
        _ = allocator;
        const client = try allocator.create(HttpClient);
        client.* = HttpClient{
            .loop = loop,
            .proxy_addr = proxy_addr,
            .target_addr = target_addr,
        };
        return client;
    }

    /// Destroy HTTP client
    pub fn destroy(self: *HttpClient, allocator: std.mem.Allocator) void {
        self.close();
        allocator.destroy(self);
    }

    /// Set callbacks
    pub fn setCallbacks(
        self: *HttpClient,
        userdata: ?*anyopaque,
        on_tunnel_ready: ?TunnelReadyCallback,
        on_data: ?*const fn (userdata: ?*anyopaque, data: []const u8) void,
        on_error: ?*const fn (userdata: ?*anyopaque, err: HttpError) void,
    ) void {
        self.userdata = userdata;
        self.on_tunnel_ready = on_tunnel_ready;
        self.on_data = on_data;
        self.on_error = on_error;
    }

    /// Get current state
    pub fn getState(self: *HttpClient) HttpState {
        return self.state;
    }

    /// Connect to proxy and establish tunnel (async)
    pub fn connect(self: *HttpClient) HttpError!void {
        std.debug.print("\n[HTTP] ============================================\n", .{});
        std.debug.print("[HTTP] connect() called\n", .{});

        // Create socket
        self.sock = std.posix.socket(
            self.proxy_addr.any.family,
            std.posix.SOCK.STREAM | std.posix.SOCK.NONBLOCK,
            0,
        ) catch |err| {
            std.debug.print("[HTTP-ERROR] socket() failed: {}\n", .{err});
            return error.SocketFailed;
        };

        std.debug.print("[HTTP] socket created: fd={}\n", .{self.sock});

        self.state = .Connecting;
        std.debug.print("[HTTP-STATE] Changed to .Connecting\n", .{});

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

        std.debug.print("[HTTP-EXIT] ============================================\n\n", .{});
    }

    /// Send data through established tunnel
    pub fn send(self: *HttpClient, data: []const u8) HttpError!void {
        if (self.state != .Ready) {
            return error.NotConnected;
        }

        self.completion = .{
            .op = .{
                .write = .{
                    .fd = self.sock,
                    .buffer = .{ .slice = data },
                },
            },
            .userdata = self,
            .callback = onWrite,
        };
        self.loop.add(&self.completion);
    }

    /// Receive data from tunnel
    pub fn recv(self: *HttpClient) HttpError![]const u8 {
        if (self.state != .Ready) {
            return error.NotConnected;
        }

        self.completion = .{
            .op = .{
                .read = .{
                    .fd = self.sock,
                    .buffer = .{ .slice = &self.read_buf },
                },
            },
            .userdata = self,
            .callback = onRead,
        };
        self.loop.add(&self.completion);

        return self.read_buf[0..self.bytes_read];
    }

    /// Close connection
    pub fn close(self: *HttpClient) void {
        if (self.sock >= 0) {
            std.posix.close(self.sock);
        }
        self.sock = -1;
        self.state = .Closed;
    }
};

/// Connect callback
fn onConnect(
    userdata: ?*anyopaque,
    loop: *xev.Loop,
    completion: *xev.Completion,
    result: xev.Result,
) xev.CallbackAction {
    _ = loop;
    _ = completion;

    const self: *HttpClient = @ptrCast(@alignCast(userdata orelse return .disarm));

    result.connect catch |err| {
        std.debug.print("[HTTP-ERROR] Connect failed: {}\n", .{err});
        self.state = .Error;
        if (self.on_error) |cb| cb(self.userdata, error.ConnectionFailed);
        return .disarm;
    };

    std.debug.print("[HTTP] TCP connection to proxy established\n", .{});

    // Send HTTP CONNECT request
    self.sendConnectRequest() catch |err| {
        std.debug.print("[HTTP-ERROR] Failed to send CONNECT: {}\n", .{err});
        self.state = .Error;
        if (self.on_error) |cb| cb(self.userdata, error.ConnectionFailed);
        return .disarm;
    };

    return .disarm;
}

/// Send HTTP CONNECT request
fn sendConnectRequest(self: *HttpClient) HttpError!void {
    // Build CONNECT request
    // CONNECT target:port HTTP/1.1\r\nHost: target:port\r\n\r\n
    const target_ip = self.target_addr.getBytes();
    const target_port = self.target_addr.getPort();

    // Format: CONNECT x.x.x.x:port HTTP/1.1
    const len = std.fmt.bufPrint(
        &self.write_buf,
        "CONNECT {d}.{d}.{d}.{d}:{d} HTTP/1.1\r\nHost: {d}.{d}.{d}.{d}:{d}\r\n\r\n",
        .{
            target_ip[0], target_ip[1], target_ip[2], target_ip[3], target_port,
            target_ip[0], target_ip[1], target_ip[2], target_ip[3], target_port,
        },
    ) catch {
        return error.NotSupported;
    };

    std.debug.print("[HTTP] Sending CONNECT request...\n", .{});
    std.debug.print("[HTTP] Request: {s}\n", .{self.write_buf[0..len]});

    self.state = .Connected;
    self.completion = .{
        .op = .{
            .write = .{
                .fd = self.sock,
                .buffer = .{ .slice = self.write_buf[0..len] },
            },
        },
        .userdata = self,
        .callback = onConnectWrite,
    };
    self.loop.add(&self.completion);
}

/// CONNECT request write callback
fn onConnectWrite(
    userdata: ?*anyopaque,
    loop: *xev.Loop,
    completion: *xev.Completion,
    result: xev.Result,
) xev.CallbackAction {
    _ = loop;
    _ = completion;

    const self: *HttpClient = @ptrCast(@alignCast(userdata orelse return .disarm));

    _ = result.write catch |err| {
        std.debug.print("[HTTP-ERROR] CONNECT write failed: {}\n", .{err});
        self.state = .Error;
        if (self.on_error) |cb| cb(self.userdata, error.ConnectionFailed);
        return .disarm;
    };

    std.debug.print("[HTTP] CONNECT request sent, waiting for response...\n", .{});

    // Read CONNECT response
    self.completion = .{
        .op = .{
            .read = .{
                .fd = self.sock,
                .buffer = .{ .slice = &self.read_buf },
            },
        },
        .userdata = self,
        .callback = onConnectResponse,
    };
    self.loop.add(&self.completion);

    return .disarm;
}

/// CONNECT response callback
fn onConnectResponse(
    userdata: ?*anyopaque,
    loop: *xev.Loop,
    completion: *xev.Completion,
    result: xev.Result,
) xev.CallbackAction {
    _ = loop;
    _ = completion;

    const self: *HttpClient = @ptrCast(@alignCast(userdata orelse return .disarm));

    const n = result.read catch |err| {
        std.debug.print("[HTTP-ERROR] CONNECT response read failed: {}\n", .{err});
        self.state = .Error;
        if (self.on_error) |cb| cb(self.userdata, error.ConnectionFailed);
        return .disarm;
    };

    if (n == 0) {
        std.debug.print("[HTTP-ERROR] CONNECT response: EOF\n", .{});
        self.state = .Error;
        if (self.on_error) |cb| cb(self.userdata, error.InvalidData);
        return .disarm;
    }

    std.debug.print("[HTTP] CONNECT response: {s}\n", .{self.read_buf[0..n]});

    // Parse HTTP response
    // Expected: HTTP/1.x 200 Connection established\r\n\r\n
    // Or: HTTP/1.x 407 Proxy Authentication Required\r\n...
    const response = std.mem.sliceTo(self.read_buf[0..n], '\r');
    std.debug.print("[HTTP] Response line: {s}\n", .{response});

    // Check for 200 OK
    if (std.mem.startsWith(u8, response, "HTTP/1.1 200") or
        std.mem.startsWith(u8, response, "HTTP/1.0 200"))
    {
        std.debug.print("[HTTP] Tunnel established!\n", .{});
        self.state = .Ready;
        if (self.on_tunnel_ready) |cb| {
            cb(self.userdata, self);
        }
    } else if (std.mem.startsWith(u8, response, "HTTP/1.1 407") or
        std.mem.startsWith(u8, response, "HTTP/1.0 407"))
    {
        std.debug.print("[HTTP-ERROR] Proxy authentication required\n", .{});
        self.state = .Error;
        if (self.on_error) |cb| cb(self.userdata, error.ConnectionFailed);
    } else {
        std.debug.print("[HTTP-ERROR] CONNECT failed: {s}\n", .{response});
        self.state = .Error;
        if (self.on_error) |cb| cb(self.userdata, error.ConnectionFailed);
    }

    return .disarm;
}

/// Data write callback
fn onWrite(
    userdata: ?*anyopaque,
    loop: *xev.Loop,
    completion: *xev.Completion,
    result: xev.Result,
) xev.CallbackAction {
    _ = loop;
    _ = completion;

    const self: *HttpClient = @ptrCast(@alignCast(userdata orelse return .disarm));
    _ = result.write catch |err| {
        std.debug.print("[HTTP-WARN] Write failed: {}\n", .{err});
        return .disarm;
    };

    return .disarm;
}

/// Data read callback
fn onRead(
    userdata: ?*anyopaque,
    loop: *xev.Loop,
    completion: *xev.Completion,
    result: xev.Result,
) xev.CallbackAction {
    _ = loop;
    _ = completion;

    const self: *HttpClient = @ptrCast(@alignCast(userdata orelse return .disarm));

    const n = result.read catch |err| {
        std.debug.print("[HTTP-ERROR] Read failed: {}\n", .{err});
        return .disarm;
    };

    if (n == 0) {
        std.debug.print("[HTTP-WARN] Connection closed\n", .{});
        self.state = .Closed;
        return .disarm;
    }

    self.bytes_read = n;

    if (self.on_data) |cb| {
        cb(self.userdata, self.read_buf[0..n]);
    }

    return .disarm;
}
