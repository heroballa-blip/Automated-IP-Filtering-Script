"""
connection_monitor.py - Active Network Connection Analyzer
Author: Harsha Balla
Description: Inspects active network connections, flags suspicious ports,
             foreign connections, and unexpected listening services.
"""

import subprocess
import sys
import re
import argparse
from datetime import datetime
from collections import defaultdict

# ── Known safe ports (customize for your environment) ────────────
SAFE_PORTS = {
    22, 80, 443, 53, 123, 67, 68,  # SSH, HTTP, HTTPS, DNS, NTP, DHCP
    8080, 8443,                      # common dev ports
}

# Ports that should never be listening externally
DANGEROUS_LISTENING = {
    23: "Telnet",
    445: "SMB",
    3389: "RDP",
    5900: "VNC",
    6379: "Redis",
    27017: "MongoDB",
    3306: "MySQL",
    5432: "PostgreSQL",
}

# Known malicious or suspicious port ranges
SUSPICIOUS_PORTS = set(range(1, 1024)) - SAFE_PORTS  # privileged ports
# ─────────────────────────────────────────────────────────────────


def get_connections():
    """Get active network connections using ss or netstat."""
    try:
        result = subprocess.run(
            ["ss", "-tunap"],
            capture_output=True, text=True, timeout=10
        )
        return parse_ss(result.stdout)
    except FileNotFoundError:
        try:
            result = subprocess.run(
                ["netstat", "-tunap"],
                capture_output=True, text=True, timeout=10
            )
            return parse_netstat(result.stdout)
        except FileNotFoundError:
            print("[ERROR] Neither 'ss' nor 'netstat' found.")
            sys.exit(1)


def parse_ss(output):
    """Parse output from 'ss -tunap'."""
    connections = []
    for line in output.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 5:
            continue
        try:
            proto  = parts[0]
            state  = parts[1]
            local  = parts[4]
            remote = parts[5] if len(parts) > 5 else "*:*"
            proc   = parts[-1] if 'users:' in line else "unknown"
            connections.append({
                "proto":  proto,
                "state":  state,
                "local":  local,
                "remote": remote,
                "proc":   proc,
            })
        except IndexError:
            continue
    return connections


def parse_netstat(output):
    """Parse output from 'netstat -tunap'."""
    connections = []
    for line in output.splitlines()[2:]:
        parts = line.split()
        if len(parts) < 6:
            continue
        try:
            connections.append({
                "proto":  parts[0],
                "state":  parts[5] if len(parts) > 5 else "UNKNOWN",
                "local":  parts[3],
                "remote": parts[4],
                "proc":   parts[-1] if len(parts) > 6 else "unknown",
            })
        except IndexError:
            continue
    return connections


def extract_port(addr):
    """Extract port number from address string like '0.0.0.0:22' or '[::]:443'."""
    try:
        return int(addr.rsplit(":", 1)[-1])
    except (ValueError, IndexError):
        return None


def is_foreign(addr):
    """Check if address is a non-local/non-loopback IP."""
    local_prefixes = ("127.", "0.0.0.0", "::", "10.", "192.168.", "172.")
    return not any(addr.startswith(p) for p in local_prefixes)


def analyze(connections):
    """Flag suspicious connections."""
    flags = []

    for conn in connections:
        issues = []
        local_port = extract_port(conn["local"])
        remote_addr = conn["remote"]

        # Check for dangerous listening services
        if conn["state"] in ("LISTEN", "UNCONN") and local_port in DANGEROUS_LISTENING:
            issues.append(f"dangerous service listening: {DANGEROUS_LISTENING[local_port]}")

        # Check for established connections to foreign IPs on suspicious ports
        if conn["state"] == "ESTABLISHED" and is_foreign(remote_addr):
            remote_port = extract_port(remote_addr)
            if remote_port and remote_port in SUSPICIOUS_PORTS:
                issues.append(f"established connection to foreign IP on suspicious port {remote_port}")

        if issues:
            flags.append({**conn, "issues": issues})

    return flags


def report(connections, flagged):
    """Print connection analysis report."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print(f"\n{'='*60}")
    print(f"  Network Connection Report | {timestamp}")
    print(f"  Total connections : {len(connections)}")
    print(f"  Flagged           : {len(flagged)}")
    print(f"{'='*60}\n")

    if not flagged:
        print("  [OK] No suspicious connections detected.\n")
        return

    for conn in flagged:
        print(f"  [!] {conn['proto']} | {conn['state']}")
        print(f"      Local  : {conn['local']}")
        print(f"      Remote : {conn['remote']}")
        print(f"      Process: {conn['proc']}")
        for issue in conn["issues"]:
            print(f"      Issue  : {issue}")
        print()


def main():
    parser = argparse.ArgumentParser(
        description="Analyze active network connections for suspicious activity"
    )
    parser.add_argument("--all", action="store_true",
                        help="Show all connections, not just flagged ones")
    args = parser.parse_args()

    print("[*] Gathering active network connections...")
    connections = get_connections()
    flagged = analyze(connections)
    report(connections, flagged)

    if args.all:
        print("\n--- All Active Connections ---\n")
        for c in connections:
            print(f"  {c['proto']:<5} {c['state']:<12} {c['local']:<25} {c['remote']}")


if __name__ == "__main__":
    main()
