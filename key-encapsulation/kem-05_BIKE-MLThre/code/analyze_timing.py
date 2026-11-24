#!/usr/bin/env python3
import csv
import json
import math
import random
import statistics
import sys


def quantile(xs, q):
    xs = sorted(xs)
    pos = (len(xs) - 1) * q
    lo = math.floor(pos)
    hi = math.ceil(pos)
    if lo == hi:
        return xs[lo]
    return xs[lo] * (hi - pos) + xs[hi] * (pos - lo)


def main(path):
    rows = []
    with open(path, newline="", encoding="ascii") as f:
        lines = f.readlines()
    start = lines.index("RAW_BEGIN\n") + 1
    for row in csv.DictReader(lines[start:]):
        rows.append({
            "valid": int(row["valid_thread_ns"]),
            "failure": int(row["failure_thread_ns"]),
        })
    ratios = [r["failure"] / r["valid"] for r in rows]
    diffs = [r["failure"] - r["valid"] for r in rows]
    rng = random.Random(20261114)
    boot_median = []
    boot_trimmed = []
    for _ in range(10000):
        sample = [ratios[rng.randrange(len(ratios))] for _ in ratios]
        sample.sort()
        trim = sample[len(sample) // 20:-len(sample) // 20]
        boot_median.append(statistics.median(sample))
        boot_trimmed.append(statistics.mean(trim))
    output = {
        "input": path,
        "pairs": len(rows),
        "valid_median_ns": statistics.median(r["valid"] for r in rows),
        "failure_median_ns": statistics.median(r["failure"] for r in rows),
        "failure_over_valid_median": statistics.median(ratios),
        "failure_minus_valid_median_ns": statistics.median(diffs),
        "bootstrap_median_ratio_ci95": [
            quantile(boot_median, 0.025), quantile(boot_median, 0.975)
        ],
        "bootstrap_20pct_trimmed_ratio_ci95": [
            quantile(boot_trimmed, 0.025), quantile(boot_trimmed, 0.975)
        ],
        "interpretation_limit": (
            "Bounded host/compiler measurement on one original 128-bit KAT; "
            "an interval containing one rejects no general constant-time claim."
        ),
    }
    print(json.dumps(output, indent=2, sort_keys=True))


if __name__ == "__main__":
    main(sys.argv[1])
