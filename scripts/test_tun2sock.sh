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
sudo "$BINARY" --tun-ip "$TUN_IP" --proxy "$PROXY" &
TUN2SOCK_PID=$!
sleep 2

# Check if process is running
if ps -p $TUN2SOCK_PID > /dev/null 2>&1; then
    echo "    tun2sock started (PID: $TUN2SOCK_PID)"
else
    echo "    ERROR: tun2sock failed to start"
    exit 1
fi
echo ""

# Step 3: Add route
echo "[3/6] Adding route for $TARGET_IP -> $TUN_IP..."
sudo route add "$TARGET_IP" "$TUN_IP" 2>/dev/null || echo "    Route may already exist"
echo "    Route added"
echo ""

# Step 4: Verify route
echo "[4/6] Verifying route..."
netstat -rn | grep "$TARGET_IP" || echo "    Route not found in routing table"
echo ""

# Step 5: Test ICMP
echo "[5/6] Testing ICMP (ping)..."
if ping -c 3 "$TARGET_IP" 2>&1; then
    echo "    ICMP ping successful"
else
    echo "    ICMP ping failed"
fi
echo ""

# Step 6: Test HTTP
echo "[6/6] Testing HTTP (curl)..."
if curl -v --connect-timeout 5 -H "Host: baidu.com" "http://$TARGET_IP/" 2>&1; then
    echo "    HTTP request successful"
else
    echo "    HTTP request failed (proxy may not be running)"
fi
echo ""

# Cleanup
echo "=== Cleanup ==="
echo "Removing route..."
sudo route delete "$TARGET_IP" 2>/dev/null || echo "    Route removal skipped"
echo "Stopping tun2sock..."
kill $TUN2SOCK_PID 2>/dev/null || echo "    Process already stopped"
echo ""

echo "=== Test Complete ==="
