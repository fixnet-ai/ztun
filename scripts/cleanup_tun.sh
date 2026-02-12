#!/bin/bash
# cleanup_tun.sh - Stop all tun2sock instances
# Usage: ./cleanup_tun.sh

echo "=== Stopping all tun2sock instances ==="

# Kill by process name (excluding current shell and claude)
PIDS=$(pgrep -f "tun2sock" 2>/dev/null || true)

if [ -z "$PIDS" ]; then
    echo "No tun2sock processes found"
    exit 0
fi

echo "Found: $PIDS"
for pid in $PIDS; do
    # Skip current shell
    if [ "$pid" = "$$" ]; then
        continue
    fi
    # Skip if it's claude
    if ps -p "$pid" -o comm= 2>/dev/null | grep -qi "claude"; then
        echo "Skipping PID $pid (claude)"
        continue
    fi
    echo "Killing PID $pid..."
    sudo kill -9 "$pid" 2>/dev/null || true
done

echo "Done"
