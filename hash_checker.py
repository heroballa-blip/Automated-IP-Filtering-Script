"""
hash_checker.py - File Integrity Monitor (FIM)
Author: Harsha Balla
Description: Computes and stores cryptographic hashes of files,
             then detects unauthorized modifications by comparing against baseline.
"""

import os
import sys
import json
import hashlib
import argparse
from datetime import datetime
from pathlib import Path

# ── Configuration ────────────────────────────────────────────────
BASELINE_FILE = "baseline.json"
HASH_ALGO     = "sha256"
# ─────────────────────────────────────────────────────────────────


def compute_hash(filepath, algo=HASH_ALGO):
    """Compute cryptographic hash of a file."""
    h = hashlib.new(algo)
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except (PermissionError, FileNotFoundError) as e:
        return f"ERROR:{e}"


def build_baseline(paths):
    """Compute hashes for all files in given paths and save as baseline."""
    baseline = {
        "created":   datetime.now().isoformat(),
        "algorithm": HASH_ALGO,
        "files":     {}
    }

    for path in paths:
        p = Path(path)
        if p.is_file():
            baseline["files"][str(p.resolve())] = compute_hash(p)
        elif p.is_dir():
            for f in p.rglob("*"):
                if f.is_file():
                    baseline["files"][str(f.resolve())] = compute_hash(f)

    with open(BASELINE_FILE, "w") as f:
        json.dump(baseline, f, indent=2)

    print(f"[+] Baseline created: {len(baseline['files'])} file(s) hashed.")
    print(f"[+] Saved to '{BASELINE_FILE}'")
    return baseline


def load_baseline():
    """Load existing baseline from disk."""
    if not os.path.exists(BASELINE_FILE):
        print(f"[ERROR] No baseline found. Run with --baseline first.")
        sys.exit(1)
    with open(BASELINE_FILE) as f:
        return json.load(f)


def verify(baseline):
    """Compare current file hashes against baseline and report changes."""
    results = {
        "modified": [],
        "deleted":  [],
        "new":      [],
    }

    checked_paths = set()

    for filepath, stored_hash in baseline["files"].items():
        p = Path(filepath)
        checked_paths.add(filepath)

        if not p.exists():
            results["deleted"].append(filepath)
            continue

        current_hash = compute_hash(p)
        if current_hash != stored_hash:
            results["modified"].append({
                "path":     filepath,
                "expected": stored_hash,
                "actual":   current_hash
            })

    report(results, baseline)
    return results


def report(results, baseline):
    """Print a formatted integrity check report."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total = len(baseline["files"])
    issues = len(results["modified"]) + len(results["deleted"]) + len(results["new"])

    print(f"\n{'='*55}")
    print(f"  File Integrity Report | {timestamp}")
    print(f"  Baseline : {baseline['created'][:19]}")
    print(f"  Files    : {total} checked | {issues} issue(s) found")
    print(f"{'='*55}\n")

    if not issues:
        print("  [OK] All files match baseline. No tampering detected.")
        return

    for item in results["modified"]:
        print(f"  [MODIFIED]  {item['path']}")
        print(f"              Expected : {item['expected'][:16]}...")
        print(f"              Actual   : {item['actual'][:16]}...")

    for path in results["deleted"]:
        print(f"  [DELETED]   {path}")

    for path in results["new"]:
        print(f"  [NEW FILE]  {path}")

    print(f"\n{'='*55}")
    print(f"  ACTION REQUIRED: {issues} integrity violation(s) detected.")
    print(f"{'='*55}\n")


def main():
    parser = argparse.ArgumentParser(
        description="File Integrity Monitor — detect unauthorized file changes"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--baseline", nargs="+", metavar="PATH",
        help="Create baseline from files/directories"
    )
    group.add_argument(
        "--verify", action="store_true",
        help="Verify current files against stored baseline"
    )
    args = parser.parse_args()

    if args.baseline:
        build_baseline(args.baseline)
    elif args.verify:
        baseline = load_baseline()
        verify(baseline)


if __name__ == "__main__":
    main()
