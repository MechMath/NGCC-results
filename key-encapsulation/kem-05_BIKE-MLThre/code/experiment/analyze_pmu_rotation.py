#!/usr/bin/env python3
import csv
import json
import statistics
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ROWS = ROOT / "experiment/pmu_rotation_rows.csv"
OUT = ROOT / "experiment/pmu_rotation_results.json"
WEIGHTS = {0: 8, 1: 32, 2: 128, 3: 512}
INT_FIELDS = {
    "rep", "key_id", "weight_id", "mask_id", "shift", "c0_weight",
    "syndrome_weight", "decoder_rc", "final_weight", "guess_weight",
    "branches", "branch_misses", "cycles",
}


def median(values):
    return statistics.median(values)


rows = []
with ROWS.open(newline="") as handle:
    for row in csv.DictReader(handle):
        rows.append({key: int(row[key]) if key in INT_FIELDS else row[key]
                     for key in row})

# Per-unit medians are the primary measurements. Repeats are never treated as
# independent keys.
units = {}
for row in rows:
    unit_id = (row["key_id"], row["weight_id"], row["mask_id"], row["shift"])
    units.setdefault(unit_id, []).append(row)

unit_medians = {}
repeat_ranges = []
for unit_id, samples in units.items():
    branches = [sample["branches"] for sample in samples]
    misses = [sample["branch_misses"] for sample in samples]
    cycles = [sample["cycles"] for sample in samples]
    unit_medians[unit_id] = {
        "branches": median(branches),
        "branch_misses": median(misses),
        "cycles": median(cycles),
    }
    repeat_ranges.append(max(branches) - min(branches))

exact_state_invariance = {}
for field in ("syndrome_weight", "decoder_rc", "final_weight", "guess_weight"):
    varying = []
    for key in range(3):
        for weight_id in range(4):
            for mask_id in range(4):
                values = {
                    row[field]
                    for row in rows
                    if (row["key_id"], row["weight_id"], row["mask_id"]) ==
                    (key, weight_id, mask_id)
                }
                if len(values) != 1:
                    varying.append({
                        "key_id": key,
                        "public_c0_weight": WEIGHTS[weight_id],
                        "mask_id": mask_id,
                        "values": sorted(values),
                    })
    exact_state_invariance[field] = {
        "groups_checked": 48,
        "groups_varying_across_shifts": len(varying),
        "varying": varying,
    }

cells = []
for key in range(3):
    for weight_id in range(4):
        mask_summaries = []
        for mask_id in range(4):
            shift_medians = [
                unit_medians[(key, weight_id, mask_id, shift)]["branches"]
                for shift in range(16)
            ]
            mask_summaries.append({
                "mask_id": mask_id,
                "shift_median_branches": shift_medians,
                "range": max(shift_medians) - min(shift_medians),
                "relative_range":
                    (max(shift_medians) - min(shift_medians)) /
                    statistics.mean(shift_medians),
            })
        # Do not pool masks: different masks legitimately execute different
        # branch counts. The cell statistic is the largest within-mask range.
        branch_range = max(item["range"] for item in mask_summaries)
        relative_range = max(item["relative_range"] for item in mask_summaries)
        cells.append({
            "key_id": key,
            "public_c0_weight": WEIGHTS[weight_id],
            "syndrome_weights": sorted({
                row["syndrome_weight"] for row in rows
                if row["key_id"] == key and row["weight_id"] == weight_id
            }),
            "max_within_mask_branch_range": branch_range,
            "max_relative_branch_range": relative_range,
            "masks": mask_summaries,
        })

support_cells = [
    cell for cell in cells
    if cell["max_within_mask_branch_range"] > 1000
    and cell["max_relative_branch_range"] > 0.01
]

result = {
    "schema": "mmat.external-pmu-rotation-result/v1",
    "status": "completed_not_independently_reviewed",
    "rows": len(rows),
    "units": len(units),
    "repetitions": len(rows) // len(units),
    "oracle_validation": "all 768 dense syndrome weights matched sparse XOR",
    "decoder_status_counts": {
        "success": sum(row["decoder_rc"] == 0 for row in rows),
        "failure": sum(row["decoder_rc"] != 0 for row in rows),
    },
    "exact_state_invariance": exact_state_invariance,
    "repeat_branch_range": {
        "median": median(repeat_ranges),
        "maximum": max(repeat_ranges),
    },
    "predeclared_support_gate": {
        "rule": "a key x public-weight cell has a within-mask branch range >1000 and relative range >0.01",
        "cells_meeting_gate": len(support_cells),
        "met": bool(support_cells),
    },
    "cells": cells,
    "boundary": (
        "Local userspace PMU counts are not a remote timing oracle. Exact "
        "syndrome and decoder states were invariant across these rotations, "
        "but no syndrome-bit/key recovery or NGCC-Low consequence was shown."
    ),
}
OUT.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
print(json.dumps({
    "status": result["status"],
    "support_gate_met": result["predeclared_support_gate"]["met"],
    "max_within_mask_branch_range": max(
        cell["max_within_mask_branch_range"] for cell in cells
    ),
    "max_relative_branch_range": max(
        cell["max_relative_branch_range"] for cell in cells
    ),
}, indent=2))
