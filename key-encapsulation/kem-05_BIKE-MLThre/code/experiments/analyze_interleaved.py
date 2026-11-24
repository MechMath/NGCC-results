#!/usr/bin/env python3
import csv
import json
import statistics
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent
LOGDIR = ROOT / "logs" / "interleaved"


def load(prefix, round_no):
    with (LOGDIR / f"{prefix}_{round_no}.csv").open(newline="") as f:
        rows = list(csv.DictReader(f))
    cells = defaultdict(list)
    for r in rows:
        cells[(int(r["key"]), int(r["ct_class"]), r["ct_fnv1a64"])].append(
            int(r["ns"])
        )
    return {k: statistics.median(v) for k, v in cells.items()}


result = {"rounds": 8, "keys": 4, "classes": 6, "reps": 8}
for stem, on_name, off_name in (
    ("reference", "ref_on", "ref_off"),
    ("optimized", "opt_on", "opt_off"),
):
    round_rows = []
    contrast_rows = []
    for round_no in range(1, result["rounds"] + 1):
        on = load(on_name, round_no)
        off = load(off_name, round_no)
        keys = sorted(on.keys() & off.keys())
        diffs = [on[k] - off[k] for k in keys]
        round_rows.append({
            "round": round_no,
            "cells": len(keys),
            "median_on_ns": statistics.median(on.values()),
            "median_off_ns": statistics.median(off.values()),
            "median_paired_difference_ns": statistics.median(diffs),
        })
        # The zero ciphertext class is the observed low-work class. Compare
        # it with all other classes to test whether the learned correction
        # changes that already-existing non-ML timing separation.
        for cls in range(1, 6):
            on_pair = [on[k] - off[k] for k in keys if k[1] == cls]
            off_low = [off[k] for k in keys if k[1] == 1]
            on_low = [on[k] for k in keys if k[1] == 1]
            off_high = [off[k] for k in keys if k[1] == cls]
            on_high = [on[k] for k in keys if k[1] == cls]
            contrast_rows.append({
                "round": round_no,
                "class": cls,
                "on_class_minus_low_ns":
                    statistics.median(on_high) - statistics.median(on_low),
                "off_class_minus_low_ns":
                    statistics.median(off_high) - statistics.median(off_low),
                "on_off_paired_median_ns": statistics.median(on_pair),
            })
    result[stem] = round_rows
    result[f"{stem}_consolidated"] = {
        "median_round_on_off_difference_ns":
            statistics.median([r["median_paired_difference_ns"]
                               for r in round_rows]),
        "class_contrasts": contrast_rows,
    }
(ROOT / "interleaved_summary.json").write_text(
    json.dumps(result, indent=2, sort_keys=True) + "\n"
)
print(json.dumps(result, indent=2, sort_keys=True))
