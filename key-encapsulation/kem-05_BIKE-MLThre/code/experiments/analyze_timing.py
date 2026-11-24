#!/usr/bin/env python3
import csv
import hashlib
import json
import statistics
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent
LOGS = ROOT / "logs"


def read_rows(path):
    with path.open(newline="") as f:
        rows = list(csv.DictReader(f))
    for r in rows:
        for k in ("profile", "key", "ct_class", "rep", "ret", "match"):
            r[k] = int(r[k])
        for k in ("rdtsc", "ns"):
            r[k] = int(r[k])
    return rows


def median(xs):
    return statistics.median(xs)


def main():
    names = ("ref_on", "ref_off", "opt_on", "opt_off")
    data = {n: read_rows(LOGS / f"{n}128.csv") for n in names}

    result = {"environment": "WSL2 x86_64, Intel Xeon w9-3495X, CPU-pinned",
              "rows": {}, "hash_alignment": {}, "class_medians": {},
              "on_off_paired": {}}
    for name, rows in data.items():
        result["rows"][name] = len(rows)
        classes = defaultdict(list)
        for r in rows:
            classes[r["ct_class"]].append(r)
        result["class_medians"][name] = {}
        for cls, rs in sorted(classes.items()):
            result["class_medians"][name][str(cls)] = {
                "n": len(rs),
                "ns_median": median([r["ns"] for r in rs]),
                "cycles_median": median([r["rdtsc"] for r in rs]),
                "success_rate": sum(r["match"] for r in rs) / len(rs),
            }

    base = data["ref_on"]
    for name in names[1:]:
        other = data[name]
        key1 = {(r["key"], r["ct_class"], r["ct_fnv1a64"]) for r in base}
        key2 = {(r["key"], r["ct_class"], r["ct_fnv1a64"]) for r in other}
        result["hash_alignment"][name] = key1 == key2

    # Compare learned-on/off at identical (key,class), using each cell's median.
    by_cell = {}
    for name in ("ref_on", "ref_off"):
        cells = defaultdict(list)
        for r in data[name]:
            cells[(r["key"], r["ct_class"], r["ct_fnv1a64"])].append(r["ns"])
        by_cell[name] = {k: median(v) for k, v in cells.items()}
    common = sorted(set(by_cell["ref_on"]) & set(by_cell["ref_off"]))
    diffs = [by_cell["ref_on"][k] - by_cell["ref_off"][k] for k in common]
    ratios = [by_cell["ref_on"][k] / by_cell["ref_off"][k] for k in common]
    result["on_off_paired"] = {
        "cells": len(common),
        "median_ns_difference": median(diffs),
        "median_ratio": median(ratios),
    }

    out = ROOT / "timing_summary.json"
    out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps(result, indent=2, sort_keys=True))
    for p in [LOGS / f"{n}128.csv" for n in names] + [
        ROOT / "timing_harness.c", Path(__file__)
    ]:
        print(hashlib.sha256(p.read_bytes()).hexdigest(), p)


if __name__ == "__main__":
    main()
