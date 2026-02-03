//! connection.zig - TCP Connection State Machine
//!
//! Provides TCP connection state management with state machine transitions.
//! Used by StaticIpstack for connection tracking.

const std = @import("std");

// TCP connection states
pub const State = enum(u8) {
    Closed = 0,
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
};

// Connection 4-tuple key
pub const ConnKey = struct {
    src_ip: u32,
    src_port: u16,
    dst_ip: u32,
    dst_port: u16,
};

// Connection flags
pub const Flags = packed struct {
    used: bool,
    ipv6: bool,
    closing: bool,
    _: u5 = 0,
};

// TCP connection (static allocation)
pub const Connection = struct {
    // 4-tuple identification
    src_ip: u32,
    src_port: u16,
    dst_ip: u32,
    dst_port: u16,

    // State machine
    state: State,

    // Sequence numbers
    local_seq: u32,
    remote_seq: u32,
    local_acked: u32,
    remote_acked: u32,

    // Window
    local_window: u32,
    remote_window: u32,

    // Activity tracking (timestamp in seconds)
    last_activity: u32,

    // Application data
    userdata: ?*anyopaque,

    // Flags
    flags: Flags,
};

// Connection event types for state machine
pub const Event = enum {
    SynReceived,
    SynAckSent,
    AckReceived,
    FinReceived,
    FinSent,
    FinAckReceived,
    RstReceived,
    Timeout,
};

// Result of state machine transition
pub const TransitionResult = enum {
    None,
    SendSyn,
    SendSynAck,
    SendAck,
    SendFin,
    SendFinAck,
    SendRst,
    NotifyAccept,
    NotifyData,
    NotifyReset,
    NotifyClose,
};

/// Initialize connection to LISTEN state
pub fn initListen(conn: *Connection, src_ip: u32, src_port: u16, dst_ip: u32, dst_port: u16) void {
    conn.* = .{
        .src_ip = src_ip,
        .src_port = src_port,
        .dst_ip = dst_ip,
        .dst_port = dst_port,
        .state = .Listen,
        .local_seq = 0,
        .remote_seq = 0,
        .local_acked = 0,
        .remote_acked = 0,
        .local_window = 65535,
        .remote_window = 65535,
        .last_activity = 0,
        .userdata = null,
        .flags = .{ .used = true, .ipv6 = false, .closing = false },
    };
}

/// Initialize connection for outgoing connection
pub fn initOutgoing(conn: *Connection, src_ip: u32, src_port: u16, dst_ip: u32, dst_port: u16) void {
    conn.* = .{
        .src_ip = src_ip,
        .src_port = src_port,
        .dst_ip = dst_ip,
        .dst_port = dst_port,
        .state = .Closed,
        .local_seq = 0,
        .remote_seq = 0,
        .local_acked = 0,
        .remote_acked = 0,
        .local_window = 65535,
        .remote_window = 65535,
        .last_activity = 0,
        .userdata = null,
        .flags = .{ .used = true, .ipv6 = false, .closing = false },
    };
}

/// Reset connection to closed state
pub fn reset(conn: *Connection) void {
    conn.* = undefined;
    conn.state = .Closed;
    conn.flags.used = false;
}

/// Check if connection is active (established or has data)
pub fn isActive(conn: *Connection) bool {
    return switch (conn.state) {
        .Established,
        .FinWait1,
        .FinWait2,
        .CloseWait,
        => true,
        else => false,
    };
}

/// Check if connection is half-open
pub fn isHalfOpen(conn: *Connection) bool {
    return switch (conn.state) {
        .SynSent,
        .SynReceived,
        => true,
        else => false,
    };
}

/// Get initial sequence number (ISN)
/// Uses simple incrementing counter for static allocation
var isn_counter: u32 = 1000;

pub fn generateIsn() u32 {
    isn_counter +%= 1;
    return isn_counter;
}

/// State machine transition
/// Returns: Action to take based on the transition
pub fn transition(conn: *Connection, event: Event) TransitionResult {
    switch (conn.state) {
        .Closed => {
            switch (event) {
                .SynReceived => {
                    conn.state = .SynReceived;
                    conn.remote_seq +%= 1; // SYN consumes one sequence
                    return .SendSynAck;
                },
                .SynSent => {
                    conn.state = .SynSent;
                    conn.local_seq = generateIsn();
                    return .SendSyn;
                },
                else => {},
            }
        },
        .Listen => {
            switch (event) {
                .SynReceived => {
                    conn.state = .SynReceived;
                    conn.local_seq = generateIsn();
                    conn.remote_seq +%= 1;
                    return .SendSynAck;
                },
                .RstReceived => {
                    return .NotifyReset;
                },
                else => {},
            }
        },
        .SynSent => {
            switch (event) {
                .AckReceived => {
                    conn.state = .Established;
                    conn.remote_seq +%= 1; // SYN was acknowledged
                    return .NotifyAccept;
                },
                .SynReceived, .SynAckSent => {
                    conn.state = .Established;
                    conn.remote_seq +%= 1;
                    return .NotifyAccept;
                },
                .RstReceived => {
                    conn.state = .Closed;
                    conn.flags.used = false;
                    return .NotifyReset;
                },
                else => {},
            }
        },
        .SynReceived => {
            switch (event) {
                .AckReceived => {
                    conn.state = .Established;
                    return .None;
                },
                .FinReceived => {
                    conn.state = .FinWait1;
                    conn.remote_seq +%= 1;
                    return .SendFin;
                },
                .RstReceived => {
                    conn.state = .Closed;
                    conn.flags.used = false;
                    return .NotifyReset;
                },
                else => {},
            }
        },
        .Established => {
            switch (event) {
                .FinReceived => {
                    conn.state = .CloseWait;
                    conn.remote_seq +%= 1;
                    return .NotifyClose;
                },
                .FinSent => {
                    conn.state = .FinWait1;
                    conn.local_seq +%= 1;
                    return .SendFin;
                },
                .AckReceived => {
                    // Update acked sequence
                    return .None;
                },
                .RstReceived => {
                    conn.state = .Closed;
                    conn.flags.used = false;
                    return .NotifyReset;
                },
                else => {},
            }
        },
        .FinWait1 => {
            switch (event) {
                .AckReceived => {
                    conn.state = .FinWait2;
                    return .None;
                },
                .FinReceived => {
                    conn.state = .Closing;
                    conn.remote_seq +%= 1;
                    return .SendFin;
                },
                .FinAckReceived => {
                    conn.state = .TimeWait;
                    return .None;
                },
                .RstReceived => {
                    conn.state = .Closed;
                    conn.flags.used = false;
                    return .NotifyReset;
                },
                else => {},
            }
        },
        .FinWait2 => {
            switch (event) {
                .FinReceived => {
                    conn.state = .TimeWait;
                    conn.remote_seq +%= 1;
                    return .SendAck;
                },
                .RstReceived => {
                    conn.state = .Closed;
                    conn.flags.used = false;
                    return .NotifyReset;
                },
                else => {},
            }
        },
        .CloseWait => {
            switch (event) {
                .FinSent => {
                    conn.state = .LastAck;
                    conn.local_seq +%= 1;
                    return .SendFin;
                },
                .RstReceived => {
                    conn.state = .Closed;
                    conn.flags.used = false;
                    return .NotifyReset;
                },
                else => {},
            }
        },
        .Closing => {
            switch (event) {
                .AckReceived => {
                    conn.state = .TimeWait;
                    return .None;
                },
                .RstReceived => {
                    conn.state = .Closed;
                    conn.flags.used = false;
                    return .NotifyReset;
                },
                else => {},
            }
        },
        .LastAck => {
            switch (event) {
                .AckReceived => {
                    conn.state = .Closed;
                    conn.flags.used = false;
                    return .None;
                },
                .RstReceived => {
                    conn.state = .Closed;
                    conn.flags.used = false;
                    return .NotifyReset;
                },
                else => {},
            }
        },
        .TimeWait => {
            switch (event) {
                .Timeout => {
                    conn.state = .Closed;
                    conn.flags.used = false;
                    return .None;
                },
                else => {},
            }
        },
    }

    return .None;
}

/// Update activity timestamp
pub fn updateActivity(conn: *Connection, timestamp: u32) void {
    conn.last_activity = timestamp;
}

/// Check if connection has timed out
pub fn hasTimedOut(conn: *Connection, timestamp: u32, idle_timeout: u32) bool {
    return timestamp -| conn.last_activity > idle_timeout;
}

/// Compare connection keys (for lookup)
pub fn keyMatch(a: *const Connection, key: *const ConnKey) bool {
    return a.src_ip == key.src_ip and
           a.src_port == key.src_port and
           a.dst_ip == key.dst_ip and
           a.dst_port == key.dst_port;
}

/// Create reverse key (for matching responses)
pub fn reverseKey(key: *const ConnKey) ConnKey {
    return .{
        .src_ip = key.dst_ip,
        .src_port = key.dst_port,
        .dst_ip = key.src_ip,
        .dst_port = key.src_port,
    };
}

/// Format state as string
pub fn stateToString(state: State) [:0]const u8 {
    return switch (state) {
        .Closed => "CLOSED",
        .Listen => "LISTEN",
        .SynSent => "SYN_SENT",
        .SynReceived => "SYN_RECEIVED",
        .Established => "ESTABLISHED",
        .FinWait1 => "FIN_WAIT_1",
        .FinWait2 => "FIN_WAIT_2",
        .CloseWait => "CLOSE_WAIT",
        .Closing => "CLOSING",
        .LastAck => "LAST_ACK",
        .TimeWait => "TIME_WAIT",
    };
}

// Unit tests
test "connection init" {
    var conn: Connection = undefined;
    initListen(&conn, 0xC0A80101, 12345, 0xC0A80102, 80);

    try std.testing.expectEqual(.Listen, conn.state);
    try std.testing.expect(conn.flags.used);
    try std.testing.expectEqual(@as(u32, 0xC0A80101), conn.src_ip);
}

test "connection reset" {
    var conn: Connection = undefined;
    initListen(&conn, 0xC0A80101, 12345, 0xC0A80102, 80);
    try std.testing.expect(conn.flags.used);

    reset(&conn);
    try std.testing.expect(!conn.flags.used);
}

test "state machine SYN" {
    var conn: Connection = undefined;
    initListen(&conn, 0xC0A80101, 12345, 0xC0A80102, 80);

    // SYN received -> send SYN-ACK
    const result = transition(&conn, .SynReceived);
    try std.testing.expectEqual(.SendSynAck, result);
    try std.testing.expectEqual(.SynReceived, conn.state);

    // ACK received -> established
    _ = transition(&conn, .AckReceived);
    try std.testing.expectEqual(.Established, conn.state);
}

test "state machine FIN" {
    var conn: Connection = undefined;
    initListen(&conn, 0xC0A80101, 12345, 0xC0A80102, 80);

    // Complete 3-way handshake
    _ = transition(&conn, .SynReceived);
    _ = transition(&conn, .AckReceived);

    // FIN received -> close wait
    _ = transition(&conn, .FinReceived);
    try std.testing.expectEqual(.CloseWait, conn.state);
}

test "key match" {
    var conn: Connection = undefined;
    initListen(&conn, 0xC0A80101, 12345, 0xC0A80102, 80);

    var key = ConnKey{
        .src_ip = 0xC0A80101,
        .src_port = 12345,
        .dst_ip = 0xC0A80102,
        .dst_port = 80,
    };

    try std.testing.expect(keyMatch(&conn, &key));
}

test "reverse key" {
    var key = ConnKey{
        .src_ip = 0xC0A80101,
        .src_port = 12345,
        .dst_ip = 0xC0A80102,
        .dst_port = 80,
    };

    const rev = reverseKey(&key);
    try std.testing.expectEqual(@as(u32, 0xC0A80102), rev.src_ip);
    try std.testing.expectEqual(@as(u16, 80), rev.src_port);
    try std.testing.expectEqual(@as(u32, 0xC0A80101), rev.dst_ip);
    try std.testing.expectEqual(@as(u16, 12345), rev.dst_port);
}

test "state string" {
    try std.testing.expectEqualStrings("ESTABLISHED", stateToString(.Established));
    try std.testing.expectEqualStrings("TIME_WAIT", stateToString(.TimeWait));
}

comptime {
    if (@import("builtin").is_test) {
        std.debug.assert(@sizeOf(Connection) > 0);
    }
}
