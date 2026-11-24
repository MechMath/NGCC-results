#!/usr/bin/env python3
import csv
import json
import math
import statistics
import sys
from collections import defaultdict


def median(xs):
    return statistics.median(xs)


def read(path):
    cells = defaultdict(list)
    with open(path, newline="") as f:
        lines = f.readlines()
        while lines and not lines[0].startswith("variant,"):
            lines.pop(0)
        for row in csv.DictReader(lines):
            sample = int(row["sample_id"])
            cells[sample].append(int(row["ns"]))
    return cells


def main():
    if len(sys.argv) != 3:
        raise SystemExit("usage: analyze_model_timing.py STOCK.csv L1JSON.csv")
    stock = read(sys.argv[1])
    l1 = read(sys.argv[2])
    common = sorted(set(stock) & set(l1))
    diffs = [median(stock[s]) - median(l1[s]) for s in common]
    ratios = [median(stock[s]) / median(l1[s]) for s in common]
    n = len(diffs)
    mean = statistics.fmean(diffs) if n else None
    stdev = statistics.stdev(diffs) if n > 1 else None
    se = stdev / math.sqrt(n) if n > 1 else None
    result = {
        "schema": "bike-mlthre-model-timing-comparison/v1",
        "cells": n,
        "repetitions_per_cell": min((len(stock[s]) for s in common), default=0),
        "stock_minus_l1json_ns": {
            "median": median(diffs) if diffs else None,
            "mean": mean,
            "mean_normal_95": [
                mean - 1.959963984540054 * se,
                mean + 1.959963984540054 * se,
            ] if se is not None else [None, None],
            "min": min(diffs) if diffs else None,
            "max": max(diffs) if diffs else None,
        },
        "median_ratio": median(ratios) if ratios else None,
        "class_medians_ns": {},
        "limits": [
            "Timing runs are local WSL2 measurements with one pinned CPU.",
            "The harness omits the diagnostic candidate logger.",
            "Model threshold differences are not proven to cause any timing difference.",
            "These are fixed-input observations, not a universal constant-time claim.",
        ],
    }
    for cls in range(6):
        ids = [s for s in common if (s - 1) % 6 == cls]
        result["class_medians_ns"][str(cls)] = {
            "cells": len(ids),
            "stock": median([median(stock[s]) for s in ids]) if ids else None,
            "l1json": median([median(l1[s]) for s in ids]) if ids else None,
            "stock_minus_l1json": median(
                [median(stock[s]) - median(l1[s]) for s in ids]
            ) if ids else None,
        }
    json.dump(result, sys.stdout, indent=2, sort_keys=True)
    print()


if __name__ == "__main__":
    main()
