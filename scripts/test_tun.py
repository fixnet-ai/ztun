#!/usr/bin/env python3
"""
test_tun.py - ICMP ping test script for ztun TUN device

Usage:
    1. Start tcpdump: sudo tcpdump -i any -w /tmp/tun_capture.pcap
    2. Run this script: sudo python3 scripts/test_tun.py
    3. Check captured packets with: tcpdump -r /tmp/tun_capture.pcap -X

This script:
1. Kills any existing test_tun processes
2. Starts test_tun in background
3. Sends ping to 10.0.0.2 (kernel routes through TUN device)
4. Waits for reply and dumps complete data
5. Exits after getting the reply
"""

import subprocess
import time
import os
import sys

# Packet sizes
IP_HEADER_SIZE = 20
ICMP_HEADER_SIZE = 8


def kill_test_tun():
    """Kill any existing test_tun processes"""
    print("[*] Killing any existing test_tun processes...")
    try:
        subprocess.run(['sudo', 'killall', '-9', 'test_tun'],
                       stderr=subprocess.DEVNULL,
                       stdout=subprocess.DEVNULL,
                       timeout=5)
    except subprocess.TimeoutExpired:
        pass
    except Exception as e:
        print(f"    Warning: {e}")
    time.sleep(0.5)


def start_test_tun():
    """Start test_tun in background"""
    print("[*] Starting test_tun in background...")
    bin_path = '/Users/modasi/works/2025/fixnet/ztun/zig-out/bin/macos/test_tun'

    # Start test_tun
    proc = subprocess.Popen(
        ['sudo', bin_path],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1
    )

    print(f"    test_tun started (PID: {proc.pid})")
    time.sleep(1)  # Wait for device creation

    return proc


def send_ping():
    """Send ping to 10.0.0.2 (kernel routes through TUN device)"""
    print("[*] Sending ping to 10.0.0.2...")
    print("    Using kernel routing to send through TUN device")

    result = subprocess.run(
        ['ping', '-c', '1', '-W', '2', '10.0.0.2'],
        capture_output=True,
        text=True,
        timeout=10
    )

    if result.returncode == 0:
        print(f"    Ping succeeded!")
        print(f"    Output: {result.stdout.strip()}")
        return True
    else:
        print(f"    Ping failed!")
        print(f"    Error: {result.stderr.strip() if result.stderr else 'No response'}")
        return False


def check_route():
    """Check if route to 10.0.0.0/24 is configured"""
    print("[*] Checking routing table...")
    result = subprocess.run(
        ['netstat', '-nr'],
        capture_output=True,
        text=True
    )

    for line in result.stdout.split('\n'):
        if '10.0.0' in line:
            print(f"    {line}")

    # Check utun interfaces
    print("\n[*] Checking TUN interfaces...")
    result = subprocess.run(
        ['ifconfig'],
        capture_output=True,
        text=True
    )

    for line in result.stdout.split('\n'):
        if 'utun' in line and '10.0.0' in line:
            print(f"    {line}")


def stop_test_tun(proc):
    """Stop test_tun process"""
    print("[*] Stopping test_tun...")
    proc.terminate()
    try:
        proc.wait(timeout=2)
    except subprocess.TimeoutExpired:
        proc.kill()
    print("    test_tun stopped")


def main():
    print("=" * 50)
    print(" ztun ICMP Echo Test Script")
    print("=" * 50)
    print()

    # Kill existing processes
    kill_test_tun()

    # Check routing
    check_route()
    print()

    # Start test_tun
    proc = start_test_tun()
    time.sleep(1)
    print()

    # Check routing after test_tun starts
    check_route()
    print()

    try:
        # Send ping (kernel routes through TUN)
        success = send_ping()

        if success:
            print("\n[+] Test PASSED - Reply received!")
        else:
            print("\n[-] Test FAILED - No reply")
            # Print test_tun output
            print("\n[*] test_tun output:")
            try:
                output, _ = proc.communicate(timeout=1)
                print(output[-2000:] if len(output) > 2000 else output)
            except subprocess.TimeoutExpired:
                pass

    finally:
        stop_test_tun(proc)


if __name__ == '__main__':
    main()
