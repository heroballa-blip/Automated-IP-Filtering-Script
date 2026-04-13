"""
ip_filter.py - Network Log Analyzer & IP Threat Detector
Author: Harsha Balla
Description: Parses network logs, checks IPs against a whitelist,
             flags suspicious activity based on behavioral patterns.
"""

import re
import sys
from collections import defaultdict
from datetime import datetime

# ── Configuration ────────────────────────────────────────────────
WHITELIST_FILE = "whitelist.txt"
LOG_FILE       = "sample_log.txt"
THRESHOLD      = 10   # requests before flagging as suspicious
OUTPUT_FILE    = "flagged_ips.txt"
# ─────────────────────────────────────────────────────────────────

IP_PATTERN = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')


def load_whitelist(path):
    """Load whitelisted IPs from file, ignoring comments and blank lines."""
    try:
        with open(path) as f:
            return {line.strip() for line in f if line.strip() and not line.startswith("#")}
    except FileNotFoundError:
        print(f"[WARNING] Whitelist file '{path}' not found. Running with empty whitelist.")
        return set()


def parse_log(path):
    """Extract IPs and their request counts from a log file."""
    ip_counts  = defaultdict(int)
    ip_lines   = defaultdict(list)

    try:
        with open(path) as f:
            for line in f:
                match = IP_PATTERN.search(line)
                if match:
                    ip = match.group()
                    ip_counts[ip] += 1
                    ip_lines[ip].append(line.strip())
    except FileNotFoundError:
        print(f"[ERROR] Log file '{path}' not found.")
        sys.exit(1)

    return ip_counts, ip_lines


def analyze(ip_counts, whitelist, threshold):
    """Flag IPs not on whitelist or exceeding request threshold."""
    flagged = {}

    for ip, count in ip_counts.items():
        reasons = []
        if ip not in whitelist:
            reasons.append("not in whitelist")
        if count >= threshold:
            reasons.append(f"high request volume ({count} requests)")
        if reasons:
            flagged[ip] = {"count": count, "reasons": reasons}

    return flagged


def report(flagged, ip_lines, output_path):
    """Print and save a report of flagged IPs."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = [f"=== IP Threat Report | {timestamp} ===\n"]

    if not flagged:
        lines.append("No suspicious IPs detected.\n")
    else:
        lines.append(f"Flagged {len(flagged)} suspicious IP(s):\n")
        for ip, data in sorted(flagged.items(), key=lambda x: -x[1]['count']):
            lines.append(f"\n[!] {ip}")
            lines.append(f"    Requests : {data['count']}")
            lines.append(f"    Reasons  : {', '.join(data['reasons'])}")
            lines.append(f"    Sample   : {ip_lines[ip][0]}")

    output = "\n".join(lines)
    print(output)

    with open(output_path, "w") as f:
        f.write(output)
    print(f"\n[+] Report saved to '{output_path}'")


def main():
    print("[*] Loading whitelist...")
    whitelist = load_whitelist(WHITELIST_FILE)
    print(f"    {len(whitelist)} trusted IPs loaded.\n")

    print(f"[*] Parsing log file: {LOG_FILE}")
    ip_counts, ip_lines = parse_log(LOG_FILE)
    print(f"    {len(ip_counts)} unique IPs found.\n")

    print("[*] Analyzing for threats...")
    flagged = analyze(ip_counts, whitelist, THRESHOLD)

    print("\n" + "─" * 50)
    report(flagged, ip_lines, OUTPUT_FILE)


if __name__ == "__main__":
    main()
