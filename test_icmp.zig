// test_icmp.zig - TUN ICMP Echo Reply Test using C Helper
// Build: zig build-exe test_icmp.zig test_icmp_help.c -lc -I.
// Run: sudo ./test_icmp
//
// This version wraps test_icmp.c completely in C helper,
// Zig only calls C functions via extern declarations.

const std = @import("std");

// ============================================================================
// C Function Declarations (extern, no header)
// ============================================================================

extern "c" fn create_utun_socket(ifname: [*]u8, max_len: usize) c_int;
extern "c" fn configure_ip(ifname: [*:0]const u8, ip: [*:0]const u8) c_int;
extern "c" fn configure_peer(ifname: [*:0]const u8, peer: [*:0]const u8) c_int;
extern "c" fn interface_up(ifname: [*:0]const u8) c_int;
extern "c" fn calc_sum(addr: [*]u16, len: c_int) u16;
extern "c" fn ip2str(ip: u32) [*:0]const u8;
extern "c" fn get_buffer() [*]u8;
extern "c" fn get_buffer_size() c_int;
extern "c" fn add_route(tun_name: [*:0]const u8) c_int;
extern "c" fn delete_route() c_int;
extern "c" fn verify_route() c_int;
extern "c" fn set_nonblocking(fd: c_int) c_int;
extern "c" fn tun_read(fd: c_int, error_code: *c_int) c_int;
extern "c" fn tun_write(fd: c_int, len: c_int, error_code: *c_int) c_int;
extern "c" fn tun_close(fd: c_int) c_int;
extern "c" fn process_packet_c(len: c_int) c_int;

// ============================================================================
// Main
// ============================================================================

pub fn main() !void {
    var tun_fd: c_int = undefined;
    var tun_name: [64]u8 = undefined;
    var n: c_int = undefined;
    var err: c_int = undefined;

    std.debug.print("=== TUN ICMP Echo Reply Test (Zig + C Helper) ===\n\n", .{});

    // Clean up routes
    _ = delete_route();

    // Create utun socket
    std.debug.print("Creating utun socket...\n", .{});
    const tun_name_ptr: [*]u8 = &tun_name;
    tun_fd = create_utun_socket(tun_name_ptr, tun_name.len);
    if (tun_fd < 0) {
        std.debug.print("Failed to create utun\n", .{});
        return error.FailedToCreateUtun;
    }

    const tun_name_z: [*:0]const u8 = @ptrCast(&tun_name);
    std.debug.print("Interface: {s}\n", .{tun_name_z});

    // Configure IP and peer
    _ = configure_ip(tun_name_z, "10.0.0.1");
    _ = configure_peer(tun_name_z, "10.0.0.2");
    _ = interface_up(tun_name_z);

    // Add route
    _ = add_route(tun_name_z);

    // Verify route
    _ = verify_route();

    // Set non-blocking
    _ = set_nonblocking(tun_fd);

    std.debug.print("\nListening for ICMP...\n", .{});
    std.debug.print("(Press Ctrl+C to stop)\n\n", .{});

    // Main loop
    while (true) {
        n = tun_read(tun_fd, &err);
        if (n < 0) {
            if (err == 35) {  // EAGAIN
                std.time.sleep(10 * std.time.ns_per_ms);
                continue;
            }
            std.debug.print("Read error\n", .{});
            break;
        }

        std.debug.print("=== Received {d} bytes ===\n", .{n});

        // Process packet in C layer
        const result = process_packet_c(n);
        if (result < 0) {
            std.debug.print("Process error\n", .{});
            break;
        }

        n = tun_write(tun_fd, n, &err);
        if (n < 0) {
            std.debug.print("Write error\n", .{});
        } else {
            std.debug.print("Sent {d} bytes\n\n", .{n});
        }
    }

    _ = tun_close(tun_fd);
}
