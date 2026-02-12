//! test_http_server.zig - Simple HTTP 200 server for testing TUN/SOCKS5 forwarding
//!
//! This test simulates a remote HTTP server that responds with 200 OK.
//! Useful for debugging whether the issue is in TUN write or SOCKS5 proxy.
//!
//! Usage:
//!   1. Start this server: sudo ./test_http_server --port 8080
//!   2. In another terminal, run tun2sock pointing to this port as target
//!   3. curl http://localhost:8080 should return "HTTP 200 OK"

const std = @import("std");

// Socket constants
const AF_INET = 2;
const SOCK_STREAM = 1;
const SOL_SOCKET = 0xffff;
const SO_REUSEADDR = 0x0004;

const HTTP_200_RESPONSE =
    "HTTP/1.1 200 OK\r\n" ++
    "Content-Type: text/plain\r\n" ++
    "Content-Length: 13\r\n" ++
    "Connection: close\r\n" ++
    "\r\n" ++
    "Hello World!\r\n";

pub const Config = struct {
    port: u16 = 8080,
    addr: []const u8 = "127.0.0.1",
};


pub fn main() !u8 {
    const config = Config{};

    std.debug.print("=== Simple HTTP 200 Server for Testing ===\n", .{});
    std.debug.print("Listening on {s}:{}\n", .{ config.addr, config.port });
    std.debug.print("Will respond with HTTP 200 OK\n\n", .{});

    // Create listener socket
    const addr = std.net.Address.parseIp4(config.addr, config.port) catch {
        std.debug.print("Error: Failed to parse address\n", .{});
        return 1;
    };

    const listener = std.posix.socket(AF_INET, SOCK_STREAM, 0) catch {
        std.debug.print("Error: Failed to create socket\n", .{});
        return 1;
    };
    defer std.posix.close(listener);

    // Set SO_REUSEADDR
    const yes: c_int = 1;
    _ = std.c.setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &yes, @sizeOf(c_int));

    std.posix.bind(listener, &addr.any, addr.getOsSockLen()) catch {
        std.debug.print("Error: Failed to bind to port {}\n", .{config.port});
        return 1;
    };

    std.posix.listen(listener, 10) catch {
        std.debug.print("Error: Failed to listen\n", .{});
        return 1;
    };

    std.debug.print("Server ready! Run: curl http://{s}:{}\n", .{ config.addr, config.port });

    // Accept loop
    while (true) {
        var client_addr: std.posix.sockaddr = undefined;
        var client_len: std.posix.socklen_t = @sizeOf(std.posix.sockaddr);

        const client = std.posix.accept(listener, &client_addr, &client_len, 0) catch {
            std.debug.print("Error: Accept failed\n", .{});
            continue;
        };

        std.debug.print("[SERVER] Client connected!\n", .{});

        // Handle client in a simple way (sync for simplicity)
        handleClient(client) catch |err| {
            std.debug.print("[SERVER] Client error: {}\n", .{err});
        };

        std.posix.close(client);
        std.debug.print("[SERVER] Client disconnected\n\n", .{});
    }

    return 0;
}

fn handleClient(client: std.posix.socket_t) !void {
    var buf: [1024]u8 = undefined;

    // Read request
    const n = std.posix.read(client, &buf) catch return;
    if (n == 0) return;

    std.debug.print("[SERVER] Received {} bytes\n", .{n});

    // Send HTTP 200 response
    const written = std.posix.write(client, HTTP_200_RESPONSE) catch return;
    std.debug.print("[SERVER] Sent {} bytes (HTTP 200 OK)\n", .{written});
}
