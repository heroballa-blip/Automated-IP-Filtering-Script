"""
port_scanner.py - TCP Port Scanner with Service Detection
Author: Harsha Balla
Description: Scans a target host for open ports, identifies common services,
             and flags potentially dangerous exposed ports.
"""

import socket
import sys
import argparse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# ── Common services and risk levels ──────────────────────────────
SERVICE_MAP = {
    21:   ("FTP",         "HIGH   - credentials transmitted in plaintext"),
    22:   ("SSH",         "LOW    - encrypted, but brute-force target"),
    23:   ("Telnet",      "CRITICAL - plaintext protocol, should never be exposed"),
    25:   ("SMTP",        "MEDIUM - mail relay, check for open relay"),
    53:   ("DNS",         "MEDIUM - check for zone transfer vulnerability"),
    80:   ("HTTP",        "MEDIUM - unencrypted web traffic"),
    110:  ("POP3",        "HIGH   - plaintext email retrieval"),
    139:  ("NetBIOS",     "HIGH   - Windows file sharing, ransomware target"),
    143:  ("IMAP",        "HIGH   - plaintext email access"),
    443:  ("HTTPS",       "LOW    - encrypted web traffic"),
    445:  ("SMB",         "CRITICAL - primary ransomware attack vector"),
    3306: ("MySQL",       "HIGH   - database should not be internet-facing"),
    3389: ("RDP",         "HIGH   - Remote Desktop, brute-force target"),
    5432: ("PostgreSQL",  "HIGH   - database should not be internet-facing"),
    6379: ("Redis",       "CRITICAL - often misconfigured with no auth"),
    8080: ("HTTP-Alt",    "MEDIUM - common dev server, check for exposure"),
    8443: ("HTTPS-Alt",   "LOW    - alternate HTTPS"),
    27017:("MongoDB",     "CRITICAL - often misconfigured with no auth"),
}
# ─────────────────────────────────────────────────────────────────


def scan_port(host, port, timeout=1.0):
    """Attempt TCP connection to a single port. Returns port if open."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return port
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None


def scan_host(host, ports, max_workers=100):
    """Scan multiple ports concurrently using a thread pool."""
    open_ports = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(scan_port, host, p): p for p in ports}
        for future in as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)
    return sorted(open_ports)


def resolve_host(host):
    """Resolve hostname to IP address."""
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        print(f"[ERROR] Cannot resolve host: {host}")
        sys.exit(1)


def report(host, ip, open_ports):
    """Print a formatted scan report."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"\n{'='*55}")
    print(f"  Port Scan Report | {timestamp}")
    print(f"  Target : {host} ({ip})")
    print(f"  Open   : {len(open_ports)} port(s)")
    print(f"{'='*55}\n")

    if not open_ports:
        print("  No open ports detected.")
        return

    for port in open_ports:
        if port in SERVICE_MAP:
            service, risk = SERVICE_MAP[port]
            print(f"  [OPEN] {port:<6} {service:<14} | Risk: {risk}")
        else:
            print(f"  [OPEN] {port:<6} {'Unknown':<14} | Risk: UNKNOWN - investigate")

    print(f"\n{'='*55}")


def parse_args():
    parser = argparse.ArgumentParser(
        description="TCP Port Scanner with service risk assessment"
    )
    parser.add_argument("host", help="Target hostname or IP address")
    parser.add_argument(
        "--ports", default="common",
        help="Port range: 'common', 'all', or '1-1024' (default: common)"
    )
    parser.add_argument("--timeout", type=float, default=1.0,
                        help="Connection timeout in seconds (default: 1.0)")
    return parser.parse_args()


def resolve_ports(port_arg):
    if port_arg == "common":
        return list(SERVICE_MAP.keys())
    elif port_arg == "all":
        return list(range(1, 65536))
    elif "-" in port_arg:
        start, end = port_arg.split("-")
        return list(range(int(start), int(end) + 1))
    else:
        return [int(p) for p in port_arg.split(",")]


def main():
    args = parse_args()
    ports = resolve_ports(args.ports)
    ip = resolve_host(args.host)

    print(f"[*] Scanning {args.host} ({ip}) — {len(ports)} port(s)...")
    open_ports = scan_host(args.host, ports, max_workers=100)
    report(args.host, ip, open_ports)


if __name__ == "__main__":
    main()
