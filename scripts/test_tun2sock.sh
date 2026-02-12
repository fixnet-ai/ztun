#!/bin/bash
# test_tun2sock.sh - Test script for tun2sock forwarding
#
# IMPORTANT: tun2sock now handles ALL route configuration via API
# DO NOT use ifconfig or route commands manually!

set -e

TUN_IP="10.0.0.1"
TUN_PEER="10.0.0.2"
PROXY="127.0.0.1:1080"
TARGET_IP="111.45.11.5"
BINARY="/Users/modasi/works/2025/fixnet/ztun/zig-out/bin/macos/tun2sock"

echo "=== ztun Test Script ==="
echo ""
echo "Configuration:"
echo "  TUN IP:    $TUN_IP"
echo "  TUN Peer:  $TUN_PEER"
echo "  Proxy:     $PROXY"
echo "  Target:    $TARGET_IP"
echo ""

# Step 1: Kill all old tun2sock instances (exclude claude processes)
echo "[1/6] Stopping any existing tun2sock instances..."
OLD_PIDS=$(pgrep -f "tun2sock" 2>/dev/null || true)
if [ -n "$OLD_PIDS" ]; then
    echo "    Found running tun2sock processes: $OLD_PIDS"
    for pid in $OLD_PIDS; do
        # Check if it's not the current shell or claude
        if [ "$pid" != "$$" ] && ! ps -p "$pid" -o comm= 2>/dev/null | grep -q "claude"; then
            echo "    Stopping PID $pid..."
            sudo kill "$pid" 2>/dev/null || true
        fi
    done
    sleep 2
else
    echo "    No existing tun2sock processes found"
fi
echo ""

# Step 2: Build
echo "[2/6] Building tun2sock..."
cd /Users/modasi/works/2025/fixnet/ztun
zig build tun2sock -Doptimize=Debug
echo "    Build successful"
echo ""

# Step 3: Start tun2sock (it handles route configuration via API)
echo "[3/6] Starting tun2sock..."
echo "    NOTE: tun2sock handles route configuration automatically via BSD Routing Socket API"
sudo "$BINARY" \
    --tun-ip "$TUN_IP" \
    --tun-peer "$TUN_PEER" \
    --proxy "$PROXY" \
    --target "$TARGET_IP" \
    --debug \
    2>&1 &
TUN2SOCK_PID=$!
sleep 3

# Check if process is running
if ps -p $TUN2SOCK_PID > /dev/null 2>&1; then
    echo "    tun2sock started (PID: $TUN2SOCK_PID)"
else
    echo "    ERROR: tun2sock failed to start"
    exit 1
fi
echo ""

# Step 4: Verify route (read-only check)
echo "[4/6] Verifying route configuration..."
echo "    Checking routing table for $TARGET_IP..."
if netstat -rn 2>/dev/null | grep -q "$TARGET_IP"; then
    echo "    Route found in routing table:"
    netstat -rn | grep "$TARGET_IP" | head -3
else
    echo "    Route may not appear immediately (BSD Routing Socket async)"
fi
echo ""

# Step 5: Test ICMP
echo "[5/6] Testing ICMP (ping to peer)..."
if timeout 3 ping -c 1 "$TUN_PEER" 2>&1; then
    echo "    ICMP successful - echo reply received from $TUN_PEER"
else
    echo "    ICMP failed - check TUN device configuration"
fi
echo ""

# Step 6: Test HTTP via TUN -> SOCKS5
echo "[6/6] Testing HTTP (traffic through TUN -> SOCKS5 proxy)..."
echo "    Target: http://$TARGET_IP/"
echo "    Expected: Traffic routes via TUN to SOCKS5 proxy"
if curl -v --connect-timeout 3 -H "Host: www.baidu.com" "http://$TARGET_IP/" 2>&1; then
    echo "    HTTP request successful - traffic routed through TUN!"
else
    echo "    HTTP request failed - check SOCKS5 proxy and tunnel"
fi
echo ""

# Cleanup
echo "=== Cleanup ==="
echo "Stopping tun2sock (PID: $TUN2SOCK_PID)..."
kill $TUN2SOCK_PID 2>/dev/null || echo "    Process already stopped"
wait $TUN2SOCK_PID 2>/dev/null || true
echo ""

echo "=== Test Complete ==="
echo ""
echo "Troubleshooting:"
echo "  - Check logs: sudo ./tun2sock --debug 2>&1 | tee /tmp/tun.log"
echo "  - View routes: netstat -rn | grep -E '(utun|10\.0\.0|111\.45\.11\.5)'"
echo "  - Kill stuck: sudo pkill -9 -f tun2sock"
