#!/usr/bin/env python3
"""
Lab 02 - Beacon Traffic Simulator
Educational use only — Co-Lin Cyber Labs

Simulates periodic HTTP beaconing behavior for network traffic analysis training.
This mimics the pattern used by C2 (Command & Control) malware without any
malicious payload. Students capture this traffic with tshark and analyze it.

Run alongside a tshark capture:
    Terminal 1: tshark -i eth0 -a duration:120 -w ~/cyber-labs/captures/scenario.pcap
    Terminal 2: python3 lab-02-simulate-traffic.py
"""

import http.client
import time
import sys

TARGET_HOST = "example.com"
TARGET_PORT = 80
TARGET_PATH = "/"
BEACON_INTERVAL = 30  # seconds between beacons

def send_beacon(beacon_num):
    """Send one HTTP GET request and return (status_code, bytes_received)."""
    conn = http.client.HTTPConnection(TARGET_HOST, TARGET_PORT, timeout=10)
    headers = {
        "Host": TARGET_HOST,
        "User-Agent": "python-requests/2.28.0",
        "Accept": "*/*",
        "Connection": "close"
    }
    conn.request("GET", TARGET_PATH, headers=headers)
    response = conn.getresponse()
    data = response.read()
    conn.close()
    return response.status, len(data)

def main():
    print(f"[Beacon Simulator] Starting... (press Ctrl+C to stop)")
    print(f"[Beacon Simulator] Target: http://{TARGET_HOST}{TARGET_PATH}")
    print(f"[Beacon Simulator] Interval: {BEACON_INTERVAL} seconds")
    print(f"[Beacon Simulator] Capture with: tshark -i eth0 -Y 'http' ...")
    print("")

    beacon_num = 0
    start_time = time.time()

    while True:
        beacon_num += 1
        elapsed = int(time.time() - start_time)
        minutes, seconds = divmod(elapsed, 60)
        timestamp = f"{minutes:02d}:{seconds:02d}"

        try:
            print(f"[{timestamp}] Sending beacon #{beacon_num} to {TARGET_HOST}...", end="", flush=True)
            status, size = send_beacon(beacon_num)
            print(f" Response: {status} OK ({size} bytes)")
        except Exception as e:
            print(f" FAILED: {e}")
            print(f"[{timestamp}] Retrying at next interval...")

        if beacon_num == 1:
            print(f"\n         Capture is running. Next beacon in {BEACON_INTERVAL} seconds...")
            print(f"         In your other terminal, run the tshark analysis commands.\n")

        time.sleep(BEACON_INTERVAL)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[Beacon Simulator] Stopped by user.")
        print("[Beacon Simulator] Check your tshark capture for the beacon traffic.")
        sys.exit(0)
