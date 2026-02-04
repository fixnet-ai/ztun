//! Simple test to verify TUN reading with native POSIX read
const std = @import("std");

pub fn main() !void {
    // Open utun4 directly
    const fd = std.posix.open("/dev/utun4", .{ .ACCMODE = .RDWR }, 0) catch {
        std.debug.print("Failed to open /dev/utun4\n", .{});
        return;
    };
    defer std.posix.close(fd);

    std.debug.print("Opened /dev/utun4, fd={}\n", .{fd});

    // Use stack buffer for reading (no malloc per packet)
    var read_buf: [1504]u8 = undefined; // 1500 + 4 bytes header space

    while (true) {
        std.debug.print("\n--- Waiting for packet ---\n", .{});

        const n = std.posix.read(fd, &read_buf) catch {
            std.debug.print("Read error\n", .{});
            break;
        };
        if (n == 0) {
            std.debug.print("EOF\n", .{});
            break;
        }

        std.debug.print("Read {} bytes total (includes 4-byte utun header)\n", .{n});

        // Print the 4-byte utun header
        if (n >= 4) {
            const af = read_buf[0];
            std.debug.print("  UTUN header: af={}, reserved[1]={}, reserved[2]={}, reserved[3]={}\n",
                .{ read_buf[0], read_buf[1], read_buf[2], read_buf[3] });
            std.debug.print("  Address family: {}\n", .{af});

            if (af != 2) {
                std.debug.print("  WARNING: Expected AF_INET=2, got {}\n", .{af});
            }
        }

        // Parse IP header starting at offset 4
        const ip_offset = 4;
        if (n >= ip_offset + 20) {
            const ver_ihl = read_buf[ip_offset];
            const version = ver_ihl >> 4;
            const ihl = ver_ihl & 0x0F;
            const protocol = read_buf[ip_offset + 9];
            const total_len = std.mem.readInt(u16, read_buf[ip_offset + 2..][0..2], .big);

            std.debug.print("  IP: version={}, ihl={}, total_len={}\n", .{ version, ihl, total_len });
            std.debug.print("  Protocol: {}\n", .{protocol});

            // Protocol names
            const proto_name = switch (protocol) {
                1 => "ICMP",
                6 => "TCP",
                17 => "UDP",
                else => "UNKNOWN",
            };
            std.debug.print("  Protocol name: {s}\n", .{proto_name});

            // Print first 64 bytes of packet for debugging
            const dump_len = @min(n, 64);
            std.debug.print("  Raw bytes [0..{}]: ", .{dump_len});
            for (read_buf[0..dump_len]) |b| {
                std.debug.print("{x:2} ", .{b});
            }
            std.debug.print("\n", .{});
        } else {
            std.debug.print("  Packet too small for IP header\n", .{});
            // Print all bytes
            const dump_len = @min(n, 32);
            std.debug.print("  Raw bytes [0..{}]: ", .{dump_len});
            for (read_buf[0..dump_len]) |b| {
                std.debug.print("{x:2} ", .{b});
            }
            std.debug.print("\n", .{});
        }
    }
}
