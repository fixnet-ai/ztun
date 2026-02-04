//! nat.zig - UDP NAT session table
//!
//! Provides connection tracking for UDP transparent proxy forwarding.
//! Uses open addressing hash table for O(1) lookup performance.

const std = @import("std");
const builtin = @import("builtin");

/// UDP NAT session - tracks a single UDP flow
pub const NatSession = struct {
    /// Original source IP (network byte order)
    src_ip: u32,
    /// Original source port
    src_port: u16,
    /// Original destination IP (network byte order)
    dst_ip: u32,
    /// Original destination port
    dst_port: u16,
    /// Mapped source port on egress interface (network byte order)
    mapped_port: u16,
    /// Egress IP for this session (network byte order)
    egress_ip: u32,
    /// Timestamp of last activity (for timeout cleanup)
    last_active: i64,
    /// Connection flags
    flags: Flags,

    /// NAT session flags
    const Flags = packed struct(u8) {
        valid: bool = true,
        reserved: u7 = 0,
    };
};

/// NAT table configuration
pub const NatConfig = struct {
    /// Egress IP address (network byte order)
    egress_ip: u32,
    /// Port range start (default: 10000, above dynamic range)
    port_range_start: u16 = 10000,
    /// Port range end (default: 60000)
    port_range_end: u16 = 60000,
    /// Session timeout in seconds
    timeout: u32 = 30,
};

/// UDP NAT session table with open addressing hash table
pub const NatTable = struct {
    /// Hash table slots
    slots: []Slot,
    /// Next available port for allocation
    next_port: u16,
    /// Current timestamp for cleanup
    timestamp: i64,
    /// Configuration
    config: NatConfig,
    /// Memory allocator
    allocator: std.mem.Allocator,

    /// Hash table slot
    const Slot = struct {
        session: NatSession,
        key_hash: u64,  // Hash of 4-tuple for quick validation
    };

    /// Create a new NAT table
    pub fn init(allocator: std.mem.Allocator, config: NatConfig, table_size: usize) !*NatTable {
        // Use table_size as-is for hash distribution
        const size = table_size;

        const self = try allocator.create(NatTable);
        errdefer allocator.destroy(self);

        self.slots = try allocator.alloc(Slot, size);
        errdefer allocator.free(self.slots);

        // Initialize slots
        for (self.slots) |*slot| {
            slot.session = NatSession{
                .src_ip = 0,
                .src_port = 0,
                .dst_ip = 0,
                .dst_port = 0,
                .mapped_port = 0,
                .egress_ip = 0,
                .last_active = 0,
                .flags = .{ .valid = false },
            };
            slot.key_hash = 0;
        }

        self.next_port = config.port_range_start;
        self.timestamp = 0;
        self.config = config;
        self.allocator = allocator;

        return self;
    }

    /// Destroy NAT table and free memory
    pub fn deinit(self: *NatTable) void {
        self.allocator.free(self.slots);
        self.allocator.destroy(self);
    }

    /// Get current timestamp (platform-dependent implementation)
    fn getTimestamp(self: *NatTable) i64 {
        if (self.timestamp == 0) {
            self.timestamp = std.time.milliTimestamp();
        }
        return self.timestamp;
    }

    /// Hash function for 4-tuple key
    fn hashKey(src_ip: u32, src_port: u16, dst_ip: u32, dst_port: u16) u64 {
        // Simple but effective hash for 4-tuple
        var h: u64 = dst_ip;
        h = (h << 32) ^ @as(u64, dst_port) << 16 ^ src_ip;
        h = (h << 16) ^ src_port;
        // Final mix
        h ^= h >> 33;
        h *= 0xff51afd7ed558ccd;
        h ^= h >> 33;
        h *= 0xc4ceb9fe1a85ec53;
        h ^= h >> 33;
        return h;
    }

    /// Lookup NAT session by 4-tuple
    /// Returns the session with mapped port for forwarding
    pub fn lookup(
        self: *NatTable,
        src_ip: u32,
        src_port: u16,
        dst_ip: u32,
        dst_port: u16,
    ) ?*NatSession {
        const h = hashKey(src_ip, src_port, dst_ip, dst_port);
        const mask = self.slots.len - 1;

        var index = h & mask;
        const start = index;

        while (true) {
            const slot = &self.slots[index];

            if (slot.session.flags.valid and slot.key_hash == h) {
                // Verify full match
                if (slot.session.src_ip == src_ip and
                    slot.session.src_port == src_port and
                    slot.session.dst_ip == dst_ip and
                    slot.session.dst_port == dst_port)
                {
                    // Update activity timestamp
                    slot.session.last_active = self.getTimestamp();
                    return &slot.session;
                }
            }

            // Move to next slot (linear probing)
            index = (index + 1) & mask;

            if (index == start) {
                // Wrapped around, not found
                return null;
            }
        }
    }

    /// Lookup session by mapped port and egress IP (for UDP response handling)
    /// Returns session if found, null otherwise
    pub fn lookupByMapped(
        self: *NatTable,
        egress_ip: u32,
        mapped_port: u16,
    ) ?*NatSession {
        for (self.slots) |*slot| {
            if (slot.session.flags.valid and
                slot.session.mapped_port == mapped_port and
                slot.session.egress_ip == egress_ip)
            {
                return &slot.session;
            }
        }
        return null;
    }

    /// Reverse lookup: find session by mapped port and original destination
    /// Used when receiving response packets
    pub fn reverseLookup(
        self: *NatTable,
        egress_ip: u32,
        mapped_port: u16,
        dst_ip: u32,
        dst_port: u16,
    ) ?*NatSession {
        // Scan all slots (brute force for reverse lookup is acceptable for cleanup)
        for (self.slots) |*slot| {
            if (slot.session.flags.valid and
                slot.session.mapped_port == mapped_port and
                slot.session.egress_ip == egress_ip and
                slot.session.dst_ip == dst_ip and
                slot.session.dst_port == dst_port)
            {
                return &slot.session;
            }
        }

        return null;
    }

    /// Allocate a new NAT session
    /// Returns error if no ports available or table is full
    pub fn insert(
        self: *NatTable,
        src_ip: u32,
        src_port: u16,
        dst_ip: u32,
        dst_port: u16,
    ) !*NatSession {
        const h = hashKey(src_ip, src_port, dst_ip, dst_port);
        const mask = self.slots.len - 1;

        var index = h & mask;
        const start = index;
        var empty_index: ?usize = null;

        while (true) {
            const slot = &self.slots[index];

            if (!slot.session.flags.valid) {
                // Found empty slot
                if (empty_index == null) {
                    empty_index = index;
                }
                break;
            }

            // Check for existing session (shouldn't happen normally)
            if (slot.key_hash == h and
                slot.session.src_ip == src_ip and
                slot.session.src_port == src_port and
                slot.session.dst_ip == dst_ip and
                slot.session.dst_port == dst_port)
            {
                // Update existing session
                slot.session.last_active = self.getTimestamp();
                return &slot.session;
            }

            // Linear probing
            index = (index + 1) & mask;

            if (index == start) {
                // Table is full
                return error.NatTableFull;
            }
        }

        // Allocate port
        const mapped_port = self.allocatePort() orelse return error.NoAvailablePort;

        // Use empty slot or wrap around to found empty
        const use_index = empty_index orelse return error.NatTableFull;
        const session = &self.slots[use_index].session;

        session.* = NatSession{
            .src_ip = src_ip,
            .src_port = src_port,
            .dst_ip = dst_ip,
            .dst_port = dst_port,
            .mapped_port = mapped_port,
            .egress_ip = self.config.egress_ip,
            .last_active = self.getTimestamp(),
            .flags = .{ .valid = true },
        };

        self.slots[use_index].key_hash = h;
        return session;
    }

    /// Allocate next available port from range
    fn allocatePort(self: *NatTable) ?u16 {
        const start = self.config.port_range_start;
        const end = self.config.port_range_end;

        var attempts: usize = 0;
        while (attempts < (end - start + 1)) {
            self.next_port += 1;
            if (self.next_port > end) {
                self.next_port = start;
            }

            // Check if port is in use
            if (!self.isPortInUse(self.next_port)) {
                return self.next_port;
            }

            attempts += 1;
        }

        return null;
    }

    /// Check if a port is currently in use
    fn isPortInUse(self: *NatTable, port: u16) bool {
        for (self.slots) |*slot| {
            if (slot.session.flags.valid and slot.session.mapped_port == port) {
                return true;
            }
        }
        return false;
    }

    /// Remove a NAT session
    pub fn remove(
        self: *NatTable,
        src_ip: u32,
        src_port: u16,
        dst_ip: u32,
        dst_port: u16,
    ) bool {
        const h = hashKey(src_ip, src_port, dst_ip, dst_port);
        const mask = self.slots.len - 1;

        var index = h & mask;
        const start = index;

        while (true) {
            const slot = &self.slots[index];

            if (slot.session.flags.valid and slot.key_hash == h) {
                if (slot.session.src_ip == src_ip and
                    slot.session.src_port == src_port and
                    slot.session.dst_ip == dst_ip and
                    slot.session.dst_port == dst_port)
                {
                    slot.session.flags.valid = false;
                    slot.key_hash = 0;
                    return true;
                }
            }

            index = (index + 1) & mask;

            if (index == start) {
                return false;
            }
        }
    }

    /// Remove session by mapped port (for cleanup)
    pub fn removeByMappedPort(self: *NatTable, mapped_port: u16) bool {
        for (self.slots) |*slot| {
            if (slot.session.flags.valid and slot.session.mapped_port == mapped_port) {
                slot.session.flags.valid = false;
                slot.key_hash = 0;
                return true;
            }
        }
        return false;
    }

    /// Clean up expired sessions
    /// Returns number of sessions removed
    pub fn cleanup(self: *NatTable) usize {
        const now = self.getTimestamp();
        const timeout_ms = @as(i64, self.config.timeout) * 1000;
        var removed: usize = 0;

        for (self.slots) |*slot| {
            if (slot.session.flags.valid) {
                if (now - slot.session.last_active > timeout_ms) {
                    slot.session.flags.valid = false;
                    slot.key_hash = 0;
                    removed += 1;
                }
            }
        }

        return removed;
    }

    /// Get session count
    pub fn count(self: *NatTable) usize {
        var c: usize = 0;
        for (self.slots) |*slot| {
            if (slot.session.flags.valid) {
                c += 1;
            }
        }
        return c;
    }

    /// Get capacity utilization percentage
    pub fn utilization(self: *NatTable) f32 {
        return @as(f32, @floatFromInt(self.count())) / @as(f32, @floatFromInt(self.slots.len));
    }
};
