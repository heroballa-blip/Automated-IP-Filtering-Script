"""
log_monitor.py - Real-Time Security Log Monitor
Author: Harsha Balla
Description: Tails a log file in real time, detects security events using
             pattern matching, and alerts on suspicious activity.
"""

import re
import time
import sys
import argparse
from datetime import datetime
from collections import defaultdict

# ── Threat Signatures ────────────────────────────────────────────
SIGNATURES = [
    {
        "name":    "Brute Force - Failed Login",
        "pattern": re.compile(r"(failed|invalid|incorrect).*(password|login|auth)", re.IGNORECASE),
        "level":   "HIGH",
    },
    {
        "name":    "SQL Injection Attempt",
        "pattern": re.compile(r"(union\s+select|or\s+1=1|drop\s+table|'--)", re.IGNORECASE),
        "level":   "CRITICAL",
    },
    {
        "name":    "Directory Traversal",
        "pattern": re.compile(r"\.\./|\.\.\\|%2e%2e", re.IGNORECASE),
        "level":   "HIGH",
    },
    {
        "name":    "Sensitive File Access",
        "pattern": re.compile(r"(\.env|passwd|shadow|id_rsa|\.git/config)", re.IGNORECASE),
        "level":   "CRITICAL",
    },
    {
        "name":    "Privilege Escalation",
        "pattern": re.compile(r"(sudo|su -|chmod 777|chown root)", re.IGNORECASE),
        "level":   "MEDIUM",
    },
    {
        "name":    "Port Scan Detected",
        "pattern": re.compile(r"(nmap|masscan|port scan|SYN flood)", re.IGNORECASE),
        "level":   "HIGH",
    },
    {
        "name":    "Malware Indicator",
        "pattern": re.compile(r"(wget|curl).*(http|ftp).*\.(sh|exe|py|ps1)", re.IGNORECASE),
        "level":   "CRITICAL",
    },
]

LEVEL_COLORS = {
    "CRITICAL": "\033[91m",  # red
    "HIGH":     "\033[93m",  # yellow
    "MEDIUM":   "\033[94m",  # blue
    "LOW":      "\033[92m",  # green
    "RESET":    "\033[0m",
}
# ─────────────────────────────────────────────────────────────────

alert_counts = defaultdict(int)


def colorize(text, level):
    color = LEVEL_COLORS.get(level, "")
    reset = LEVEL_COLORS["RESET"]
    return f"{color}{text}{reset}"


def check_line(line, line_num):
    """Run all signatures against a single log line."""
    alerts = []
    for sig in SIGNATURES:
        if sig["pattern"].search(line):
            alerts.append(sig)
    return alerts


def alert(line, line_num, sig):
    """Print a formatted security alert."""
    timestamp = datetime.now().strftime("%H:%M:%S")
    level = sig["level"]
    alert_counts[level] += 1

    header = colorize(f"[{level}]", level)
    print(f"\n{header} {timestamp} — {sig['name']}")
    print(f"  Line {line_num}: {line.strip()}")


def tail_file(path, poll_interval=0.5):
    """Tail a file, yielding new lines as they appear."""
    try:
        with open(path) as f:
            f.seek(0, 2)  # seek to end
            line_num = 0
            while True:
                line = f.readline()
                if line:
                    line_num += 1
                    yield line_num, line
                else:
                    time.sleep(poll_interval)
    except FileNotFoundError:
        print(f"[ERROR] File not found: {path}")
        sys.exit(1)
    except KeyboardInterrupt:
        pass


def scan_existing(path):
    """Scan existing file contents before tailing."""
    try:
        with open(path) as f:
            for i, line in enumerate(f, 1):
                alerts = check_line(line, i)
                for sig in alerts:
                    alert(line, i, sig)
    except FileNotFoundError:
        print(f"[ERROR] File not found: {path}")
        sys.exit(1)


def summary():
    """Print alert summary on exit."""
    print(f"\n\n{'='*45}")
    print("  Session Summary")
    print(f"{'='*45}")
    total = sum(alert_counts.values())
    if total == 0:
        print("  No threats detected.")
    else:
        for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            count = alert_counts.get(level, 0)
            if count:
                print(f"  {colorize(level, level):<20} {count} alert(s)")
    print(f"{'='*45}\n")


def main():
    parser = argparse.ArgumentParser(description="Real-time security log monitor")
    parser.add_argument("logfile", nargs="?", default="sample_auth.log",
                        help="Path to log file (default: sample_auth.log)")
    parser.add_argument("--scan-history", action="store_true",
                        help="Scan existing file content before monitoring new lines")
    args = parser.parse_args()

    print(f"[*] Starting log monitor on: {args.logfile}")
    print(f"[*] Loaded {len(SIGNATURES)} threat signatures")
    print(f"[*] Press Ctrl+C to stop\n{'─'*45}")

    if args.scan_history:
        print("[*] Scanning existing log entries...")
        scan_existing(args.logfile)
        print("[*] Historical scan complete. Monitoring new entries...\n")

    try:
        for line_num, line in tail_file(args.logfile):
            alerts = check_line(line, line_num)
            for sig in alerts:
                alert(line, line_num, sig)
    except KeyboardInterrupt:
        pass
    finally:
        summary()


if __name__ == "__main__":
    main()
