#!/usr/bin/env python3
import csv
import json
import math
import sys
from collections import defaultdict
from pathlib import Path


def read_trajectory(path):
    rows = defaultdict(lambda: defaultdict(list))
    with open(path, newline="") as f:
        for row in csv.DictReader(f):
            sample = int(row["sample_id"])
            iteration = int(row["iteration"])
            rows[sample][iteration].append(row)
    return rows


def selected_state(iter_rows):
    # Candidate rows share the selected-state features. Keep the unique
    # applied threshold and feature tuple, not candidate ranking metadata.
    fields = (
        "security_level",
        "iteration",
        "initial_syndrome_weight",
        "prev_syndrome_weight",
        "current_syndrome_weight",
        "syndrome_delta",
        "z0",
        "z1",
        "var_threshold",
        "lower_bound",
        "applied_threshold",
    )
    tuples = {tuple(int(r[k]) for k in fields) for r in iter_rows}
    if len(tuples) != 1:
        raise ValueError(f"selected-state mismatch within iteration: {tuples}")
    return next(iter(tuples))


def read_outcomes(path):
    out = {}
    with open(path, newline="") as f:
        lines = f.readlines()
        while lines and not lines[0].startswith("variant,"):
            lines.pop(0)
        for row in csv.DictReader(lines):
            out[int(row["sample_id"])] = row
    return out


def wilson(k, n):
    if n == 0:
        return [None, None]
    z = 1.959963984540054
    p = k / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return [(c - half) / d, (c + half) / d]


def main():
    if len(sys.argv) != 5:
        raise SystemExit(
            "usage: analyze_model_traces.py STOCK_ITER_CSV L1_ITER_CSV "
            "STOCK_OUTCOMES L1_OUTCOMES"
        )
    stock = read_trajectory(sys.argv[1])
    l1 = read_trajectory(sys.argv[2])
    stock_out = read_outcomes(sys.argv[3])
    l1_out = read_outcomes(sys.argv[4])

    common = sorted(set(stock) & set(l1))
    differing_samples = []
    first_divergences = []
    iteration_pairs = 0
    feature_differences = defaultdict(int)
    divergence_by_class = defaultdict(int)
    divergence_by_first_iteration = defaultdict(int)
    applied_threshold_deltas = defaultdict(int)
    state_feature_names = (
        "security_level",
        "iteration",
        "initial_syndrome_weight",
        "prev_syndrome_weight",
        "current_syndrome_weight",
        "syndrome_delta",
        "z0",
        "z1",
        "var_threshold",
        "lower_bound",
        "applied_threshold",
    )

    for sample in common:
        first = None
        for iteration in sorted(set(stock[sample]) & set(l1[sample])):
            a = selected_state(stock[sample][iteration])
            b = selected_state(l1[sample][iteration])
            iteration_pairs += 1
            if a != b:
                for name, av, bv in zip(state_feature_names, a, b):
                    if av != bv:
                        feature_differences[name] += 1
                applied_threshold_deltas[a[-1] - b[-1]] += 1
                if first is None:
                    first = {
                        "sample_id": sample,
                        "iteration": iteration,
                        "stock": list(a),
                        "l1json": list(b),
                    }
                    first_divergences.append(first)
                    cls = stock_out.get(sample, {}).get("ct_class")
                    divergence_by_class[str(cls)] += 1
                    divergence_by_first_iteration[str(iteration)] += 1
        if first is not None:
            differing_samples.append(sample)

    outcome_diffs = []
    for sample in common:
        a = stock_out.get(sample)
        b = l1_out.get(sample)
        if a is None or b is None or (
            a["ret"], a["match"], a["ss_fnv1a64"]
        ) != (
            b["ret"], b["match"], b["ss_fnv1a64"]
        ):
            outcome_diffs.append({
                "sample_id": sample,
                "stock": a,
                "l1json": b,
            })

    n = len(common)
    k = len(differing_samples)
    result = {
        "schema": "bike-mlthre-model-trajectory-comparison/v1",
        "common_samples": n,
        "iteration_pairs_compared": iteration_pairs,
        "samples_with_state_divergence": k,
        "state_divergence_fraction": k / n if n else None,
        "state_divergence_wilson95": wilson(k, n),
        "terminal_outcome_differences": len(outcome_diffs),
        "first_divergences": first_divergences[:32],
        "outcome_differences": outcome_diffs[:32],
        "feature_difference_counts": dict(feature_differences),
        "divergence_by_ct_class": dict(divergence_by_class),
        "divergence_by_first_iteration": dict(divergence_by_first_iteration),
        "applied_threshold_delta_counts_stock_minus_l1json":
            {str(k): v for k, v in sorted(applied_threshold_deltas.items())},
        "stock_terminal_match_counts": {
            "success": sum(r["match"] == "1" for r in stock_out.values()),
            "fallback": sum(r["match"] == "0" for r in stock_out.values()),
        },
        "l1json_terminal_match_counts": {
            "success": sum(r["match"] == "1" for r in l1_out.values()),
            "fallback": sum(r["match"] == "0" for r in l1_out.values()),
        },
        "limits": [
            "All observations are local, deterministic 128-bit test inputs.",
            "State logging is enabled only in the diagnostic copies.",
            "Divergence is not by itself a security impact.",
            "The sample is not evidence of constant time or a general theorem.",
        ],
    }
    json.dump(result, sys.stdout, indent=2, sort_keys=True)
    print()


if __name__ == "__main__":
    main()
