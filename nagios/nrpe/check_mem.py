#!/usr/bin/env python3
"""Lightweight Nagios-compatible memory utilization plugin reading /proc/meminfo."""

from __future__ import annotations

import argparse
import sys


def read_meminfo(path: str = "/proc/meminfo") -> dict[str, int]:
    """Parse key/value kB entries from Linux /proc/meminfo."""
    values: dict[str, int] = {}
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            if ":" not in line:
                continue
            key, rest = line.split(":", 1)
            parts = rest.strip().split()
            if not parts:
                continue
            try:
                values[key.strip()] = int(parts[0])
            except ValueError:
                continue
    return values


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check Linux memory utilization via /proc/meminfo")
    parser.add_argument("-w", "--warning", type=float, default=80.0, help="Warning used %% threshold")
    parser.add_argument("-c", "--critical", type=float, default=90.0, help="Critical used %% threshold")
    parser.add_argument("--meminfo", default="/proc/meminfo", help="Path to meminfo file")
    args = parser.parse_args(argv)

    if args.warning < 0 or args.critical < 0 or args.warning > args.critical:
        print("UNKNOWN: invalid warning/critical thresholds")
        return 3

    try:
        info = read_meminfo(args.meminfo)
        total_kb = info["MemTotal"]
        avail_kb = info.get("MemAvailable")
        if avail_kb is None:
            avail_kb = info.get("MemFree", 0) + info.get("Buffers", 0) + info.get("Cached", 0)
        if total_kb <= 0:
            print("UNKNOWN: MemTotal is <= 0")
            return 3
    except Exception as exc:  # noqa: BLE001
        print(f"UNKNOWN: unable to read memory statistics ({exc})")
        return 3

    used_kb = max(0, total_kb - avail_kb)
    used_pct = round((used_kb / total_kb) * 100.0, 1)
    total_mb = round(total_kb / 1024.0, 1)
    used_mb = round(used_kb / 1024.0, 1)
    avail_mb = round(avail_kb / 1024.0, 1)

    perf = (
        f"mem_used_pct={used_pct}%;{args.warning};{args.critical};0;100 "
        f"mem_used_mb={used_mb}MB;;;0;{total_mb} mem_avail_mb={avail_mb}MB"
    )
    if used_pct >= args.critical:
        print(f"MEMORY CRITICAL - {used_pct}% used ({used_mb}/{total_mb} MB) | {perf}")
        return 2
    if used_pct >= args.warning:
        print(f"MEMORY WARNING - {used_pct}% used ({used_mb}/{total_mb} MB) | {perf}")
        return 1

    print(f"MEMORY OK - {used_pct}% used ({used_mb}/{total_mb} MB) | {perf}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
