#!/usr/bin/env python3
import csv
import collections
import json
import math
import random
import statistics

ROWS = "experiment/multikey_rows.csv"
META = "experiment/multikey_meta.json"
RNG = random.Random(0x12851)


def mean(xs):
    return sum(xs) / len(xs)


def percentile(xs, q):
    xs = sorted(xs)
    return xs[round((len(xs) - 1) * q)]


def ranks(xs):
    order = sorted(range(len(xs)), key=xs.__getitem__)
    ans = [0.0] * len(xs)
    i = 0
    while i < len(xs):
        j = i + 1
        while j < len(xs) and xs[order[j]] == xs[order[i]]:
            j += 1
        rank = (i + j - 1) / 2.0 + 1.0
        for p in order[i:j]:
            ans[p] = rank
        i = j
    return ans


def pearson(xs, ys):
    mx, my = mean(xs), mean(ys)
    num = sum((x - mx) * (y - my) for x, y in zip(xs, ys))
    dx = sum((x - mx) ** 2 for x in xs)
    dy = sum((y - my) ** 2 for y in ys)
    return num / math.sqrt(dx * dy) if dx and dy else 0.0


def spearman(xs, ys):
    return pearson(ranks(xs), ranks(ys))


def auc_high_slower(high, low):
    return sum((h > l) + 0.5 * (h == l) for h in high for l in low) / (
        len(high) * len(low)
    )


raw = list(csv.DictReader(open(ROWS, newline="")))
by_sample = collections.defaultdict(list)
for row in raw:
    by_sample[int(row["sample_id"])].append(row)

samples = []
for rows in by_sample.values():
    first = dict(rows[0])
    cycles = [float(r["cycles"]) for r in rows]
    ns = [float(r["ns"]) for r in rows]
    first.update(
        key_id=int(first["key_id"]),
        stratum=int(first["stratum"]),
        mask_id=int(first["mask_id"]),
        c0_weight=int(first["c0_weight"]),
        syndrome_weight=int(first["syndrome_weight"]),
        cycle_median=statistics.median(cycles),
        cycle_min=min(cycles),
        ns_median=statistics.median(ns),
        within_cv=statistics.pstdev(cycles) / mean(cycles),
    )
    samples.append(first)

cells = collections.defaultdict(list)
for sample in samples:
    cells[(sample["key_id"], sample["stratum"])].append(sample)


def cell_rho(cell):
    return spearman(
        [s["syndrome_weight"] for s in cell],
        [s["cycle_median"] for s in cell],
    )


def cell_auc(cell):
    med = statistics.median(s["syndrome_weight"] for s in cell)
    high = [s["cycle_median"] for s in cell if s["syndrome_weight"] > med]
    low = [s["cycle_median"] for s in cell if s["syndrome_weight"] <= med]
    return auc_high_slower(high, low) if high and low else None


def weighted_rho(cell_list):
    vals = [(len(c), cell_rho(c)) for c in cell_list]
    return sum(n * rho for n, rho in vals) / sum(n for n, _ in vals)


def weighted_auc(cell_list):
    total = 0.0
    weight = 0
    for cell in cell_list:
        med = statistics.median(s["syndrome_weight"] for s in cell)
        high = [s["cycle_median"] for s in cell if s["syndrome_weight"] > med]
        low = [s["cycle_median"] for s in cell if s["syndrome_weight"] <= med]
        if high and low:
            w = len(high) * len(low)
            total += w * auc_high_slower(high, low)
            weight += w
    return total / weight


def standardized_halves(cell_list):
    high_all, low_all = [], []
    for cell in cell_list:
        scale = statistics.median(s["cycle_median"] for s in cell)
        med = statistics.median(s["syndrome_weight"] for s in cell)
        for s in cell:
            value = s["cycle_median"] / scale
            if s["syndrome_weight"] > med:
                high_all.append(value)
            else:
                low_all.append(value)
    return high_all, low_all


def histogram_overlap(a, b, bins=20):
    lo = min(a + b)
    hi = max(a + b)
    width = (hi - lo) / bins
    hist_a = [0] * bins
    hist_b = [0] * bins
    for values, hist in ((a, hist_a), (b, hist_b)):
        for value in values:
            idx = min(bins - 1, int((value - lo) / width))
            hist[idx] += 1
    return sum(
        min(x / len(a), y / len(b)) for x, y in zip(hist_a, hist_b)
    )


def bootstrap_cells(cell_list, statistic, n=1000):
    vals = []
    for _ in range(n):
        boot = []
        for cell in cell_list:
            boot.append([cell[RNG.randrange(len(cell))] for _ in cell])
        vals.append(statistic(boot))
    vals.sort()
    return [vals[24], vals[974]]


def permutation_rho(cell_list, observed, n=1000):
    count = 0
    for _ in range(n):
        shuffled = []
        for cell in cell_list:
            ys = [s["cycle_median"] for s in cell]
            RNG.shuffle(ys)
            shuffled.append(
                [dict(s, cycle_median=y) for s, y in zip(cell, ys)]
            )
        if abs(weighted_rho(shuffled)) >= abs(observed):
            count += 1
    return (count + 1) / (n + 1)


def key_result(k):
    key_cells = [cells[(k, i)] for i in range(7)]
    all_key = [s for cell in key_cells for s in cell]
    rho = weighted_rho(key_cells)
    auc = weighted_auc(key_cells)
    cell_summary = []
    for i, cell in enumerate(key_cells):
        med = statistics.median(s["syndrome_weight"] for s in cell)
        high = [s["cycle_median"] for s in cell if s["syndrome_weight"] > med]
        low = [s["cycle_median"] for s in cell if s["syndrome_weight"] <= med]
        cell_summary.append({
            "public_c0_weight": cell[0]["c0_weight"],
            "syndrome_weight_min": min(s["syndrome_weight"] for s in cell),
            "syndrome_weight_max": max(s["syndrome_weight"] for s in cell),
            "rho": cell_rho(cell),
            "auc_high_slower": auc_high_slower(high, low),
            "median_cycle_all": statistics.median(s["cycle_median"] for s in cell),
            "median_cycle_high": statistics.median(high),
            "median_cycle_low": statistics.median(low),
            "high_minus_low_fraction": (
                statistics.median(high) - statistics.median(low)
            ) / statistics.median(s["cycle_median"] for s in cell),
            "within_cv_median": statistics.median(s["within_cv"] for s in cell),
        })
    return {
        "key_id": k,
        "raw_overall_rho": spearman(
            [s["syndrome_weight"] for s in all_key],
            [s["cycle_median"] for s in all_key],
        ),
        "matched_public_weight_rho": rho,
        "rho_bootstrap_95ci": bootstrap_cells(key_cells, weighted_rho),
        "matched_public_weight_auc_high_slower": auc,
        "auc_bootstrap_95ci": bootstrap_cells(key_cells, weighted_auc),
        "within_cv_median": statistics.median(s["within_cv"] for s in all_key),
        "cells": cell_summary,
    }


all_cells = [cells[(k, i)] for k in range(3) for i in range(7)]
pooled_rho = weighted_rho(all_cells)
pooled_auc = weighted_auc(all_cells)
key_results = [key_result(k) for k in range(3)]
pooled_high, pooled_low = standardized_halves(all_cells)

# Monotonicity of each key's public-density medians, and cell median exact weight.
monotonicity = []
for k in range(3):
    meds = []
    for i in range(7):
        cell = cells[(k, i)]
        meds.append({
            "public_c0_weight": cell[0]["c0_weight"],
            "median_syndrome_weight": statistics.median(
                s["syndrome_weight"] for s in cell
            ),
            "median_cycles": statistics.median(s["cycle_median"] for s in cell),
        })
    monotonicity.append({
        "key_id": k,
        "median_syndrome_increasing": all(
            meds[i]["median_syndrome_weight"] < meds[i + 1]["median_syndrome_weight"]
            for i in range(6)
        ),
        "median_cycles_increasing": all(
            meds[i]["median_cycles"] < meds[i + 1]["median_cycles"]
            for i in range(6)
        ),
        "spearman_density_median_syndrome_vs_cycles": spearman(
            [m["median_syndrome_weight"] for m in meds],
            [m["median_cycles"] for m in meds],
        ),
        "points": meds,
    })

result = {
    "schema": "mmat.multikey-timing-replication/v1",
    "status": "measurement_completed_analysis_not_independently_reviewed",
    "claim_boundary": (
        "Replicated evaluator-known exact syndrome-weight timing leakage in the "
        "original reference BIKE-MLThre 128 decapsulation on this host. This is "
        "not syndrome-bit recovery, h0 recovery, a remote attack, or NGCC Low impact."
    ),
    "design": {
        "keys": 3,
        "public_c0_weights": [8, 16, 32, 64, 128, 256, 512],
        "masks_per_key_stratum": 48,
        "retained_masks": len(samples),
        "repetitions_per_mask": 3,
        "retained_decapsulations": len(raw),
        "syndrome_weight_range": [
            min(s["syndrome_weight"] for s in samples),
            max(s["syndrome_weight"] for s in samples),
        ],
        "all_dec_status_zero": all(int(r["dec_status"]) == 0 for r in raw),
        "oracle_validation": "all retained masks passed exact-vs-sparse weight equality",
    },
    "pooled": {
        "raw_overall_rho": spearman(
            [s["syndrome_weight"] for s in samples],
            [s["cycle_median"] for s in samples],
        ),
        "matched_public_weight_key_cell_rho": pooled_rho,
        "rho_bootstrap_95ci": bootstrap_cells(all_cells, weighted_rho),
        "rho_within_cell_permutation_p_two_sided": permutation_rho(
            all_cells, pooled_rho
        ),
        "matched_public_weight_auc_high_slower": pooled_auc,
        "auc_bootstrap_95ci": bootstrap_cells(all_cells, weighted_auc),
        "standardized_cycle_high_median": statistics.median(pooled_high),
        "standardized_cycle_low_median": statistics.median(pooled_low),
        "standardized_cycle_high_iqr": [
            percentile(pooled_high, 0.25),
            percentile(pooled_high, 0.75),
        ],
        "standardized_cycle_low_iqr": [
            percentile(pooled_low, 0.25),
            percentile(pooled_low, 0.75),
        ],
        "standardized_histogram_overlap": histogram_overlap(
            pooled_high, pooled_low
        ),
        "within_mask_cv_median": statistics.median(
            s["within_cv"] for s in samples
        ),
    },
    "per_key": key_results,
    "monotonicity": monotonicity,
    "limitations": [
        "Three deterministic independently seeded keys on one WSL2 host.",
        "Three repetitions per exact mask; stratified bootstrap resamples masks within key/public-weight cells and does not treat repetitions as independent keys.",
        "TSC and wall time are noisy and include the complete original decapsulation call.",
        "Ground-truth syndrome weight is computed evaluator-side; it is not an attacker input.",
        "No timing-to-syndrome-bits decoder, key recovery, or remote measurement was performed.",
    ],
    "artifacts": {
        "rows": ROWS,
        "input_zip_sha256": "3a5d97532003786374b68b39779cff4e4938f593fef9596f171652c6ff593917",
        "protocol": "experiment/predeclared_protocol.json",
    },
}

with open("experiment/multikey_results.json", "w") as fp:
    json.dump(result, fp, indent=2, sort_keys=True)
    fp.write("\n")
print(json.dumps(result, indent=2, sort_keys=True))
