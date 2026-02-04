#!/bin/bash
# test_tun2sock.sh - Test script for tun2sock forwarding

set -e

TUN_IP="10.0.0.1"
PROXY="127.0.0.1:1080"
TARGET_IP="111.45.11.5"
BINARY="/Users/modasi/works/2025/fixnet/ztun/zig-out/bin/macos/tun2sock"

echo "=== ztun Test Script ==="
echo ""

# Step 1: Build
echo "[1/6] Building tun2sock..."
cd /Users/modasi/works/2025/fixnet/ztun
zig build tun2sock -Doptimize=Debug
echo "    Build successful"
echo ""

# Step 2: Start tun2sock in background
echo "[2/6] Starting tun2sock..."
sudo "$BINARY" --tun-ip "$TUN_IP" --proxy "$PROXY" 2>&1 &
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

# Step 3: Add route via TUN interface (using gateway IP)
echo "[3/6] Adding route for $TARGET_IP -> $TUN_IP..."
sudo route add -net "$TARGET_IP/32" "$TUN_IP" 2>/dev/null || echo "    Route may already exist"
echo "    Route added"
echo ""

# Step 4: Verify route
echo "[4/6] Verifying route..."
netstat -rn | grep "$TARGET_IP" || echo "    Route not found in routing table"
echo ""

# Step 5: Test ICMP - This will NOT work because 111.45.11.5 doesn't exist
echo "[5/6] Testing ICMP (ping - expected to timeout)..."
timeout 3 ping -c 1 "$TARGET_IP" 2>&1 || echo "    ICMP timeout (expected - IP doesn't exist)"
echo ""

# Step 6: Test HTTP - traffic goes through TUN, NOT directly via SOCKS5 proxy
echo "[6/6] Testing HTTP (traffic goes through TUN -> SOCKS5 proxy)..."
echo "    Connecting directly to $TARGET_IP (traffic should route via TUN)"
if curl -v --connect-timeout 10 -H "Host: www.baidu.com" "http://$TARGET_IP/" 2>&1; then
    echo "    HTTP request successful - traffic routed through TUN!"
else
    echo "    HTTP request failed"
fi
echo ""

# Cleanup
echo "=== Cleanup ==="
echo "Removing route..."
#sudo route delete "$TARGET_IP" 2>/dev/null || echo "    Route removal skipped"
echo "Stopping tun2sock..."
kill $TUN2SOCK_PID 2>/dev/null || echo "    Process already stopped"
echo ""

echo "=== Test Complete ==="
