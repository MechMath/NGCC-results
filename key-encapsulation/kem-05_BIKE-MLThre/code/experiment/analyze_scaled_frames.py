#!/usr/bin/env python3
import csv
import json
import math
import random
import statistics

FRAMES = [
    {
        "name": "supported_256_key42",
        "csv": "experiment/timing_rows_256_quick.csv",
        "meta": "experiment/timing_meta_256_quick.json",
        "security_bits": 256,
        "r_bits": 40973,
        "dv": 137,
        "key_seed": "42 repeated 48 bytes",
    },
    {
        "name": "supported_256_key67",
        "csv": "experiment/timing_rows_256_key67.csv",
        "meta": "experiment/timing_meta_256_key67.json",
        "security_bits": 256,
        "r_bits": 40973,
        "dv": 137,
        "key_seed": "67 repeated 48 bytes",
    },
    {
        "name": "supported_512_key67",
        "csv": "experiment/timing_rows_512_key67.csv",
        "meta": "experiment/timing_meta_512_key67.json",
        "security_bits": 512,
        "r_bits": 150001,
        "dv": 273,
        "key_seed": "67 repeated 48 bytes",
    },
]

RNG = random.Random(0x512256128)


def mean(values):
    return sum(values) / len(values)


def pearson(xs, ys):
    mx, my = mean(xs), mean(ys)
    numerator = sum((x - mx) * (y - my) for x, y in zip(xs, ys))
    dx = sum((x - mx) ** 2 for x in xs)
    dy = sum((y - my) ** 2 for y in ys)
    return numerator / math.sqrt(dx * dy) if dx and dy else 0.0


def rankdata(values):
    order = sorted(range(len(values)), key=values.__getitem__)
    ranks = [0.0] * len(values)
    i = 0
    while i < len(values):
        j = i + 1
        while j < len(values) and values[order[j]] == values[order[i]]:
            j += 1
        rank = (i + j - 1) / 2.0 + 1.0
        for k in range(i, j):
            ranks[order[k]] = rank
        i = j
    return ranks


def spearman(xs, ys):
    return pearson(rankdata(xs), rankdata(ys))


def bootstrap_ci(xs, ys, n=2000):
    values = []
    for _ in range(n):
        idx = [RNG.randrange(len(xs)) for _ in range(len(xs))]
        values.append(spearman([xs[i] for i in idx], [ys[i] for i in idx]))
    values.sort()
    return [values[49], values[1949]]


def permutation_p(xs, ys, observed, n=5000):
    shuffled = list(ys)
    extreme = 0
    for _ in range(n):
        RNG.shuffle(shuffled)
        if abs(spearman(xs, shuffled)) >= abs(observed):
            extreme += 1
    return (extreme + 1) / (n + 1)


frames = []
for frame in FRAMES:
    with open(frame["csv"], newline="") as handle:
        rows = list(csv.DictReader(handle))
    one = [row for row in rows if int(row["kind"]) == 1]
    zero = [row for row in rows if int(row["kind"]) == 0]
    if len(one) != frame["dv"]:
        raise SystemExit(
            f"{frame['name']}: expected {frame['dv']} one-bit rows, got {len(one)}"
        )
    if {int(row["syndrome_weight"]) for row in one} != {frame["dv"]}:
        raise SystemExit(f"{frame['name']}: one-bit syndrome weight is not DV")
    positions = [int(row["pos_a"]) for row in one]
    cycles = [int(row["cycles"]) for row in one]
    nanoseconds = [int(row["ns"]) for row in one]
    circular_distance = [
        min(position, frame["r_bits"] - position) for position in positions
    ]
    rho_position = spearman(positions, cycles)
    rho_distance = spearman(circular_distance, cycles)
    frames.append(
        {
            **frame,
            "rows": len(rows),
            "one_bit_rows": len(one),
            "zero_rows": len(zero),
            "repetitions": 1,
            "syndrome_weight_one_bit": frame["dv"],
            "cycles_median": statistics.median(cycles),
            "cycles_min": min(cycles),
            "cycles_max": max(cycles),
            "cycles_max_over_min": max(cycles) / min(cycles),
            "nanoseconds_median": statistics.median(nanoseconds),
            "zero_cycles": int(zero[0]["cycles"]),
            "position_vs_cycles_spearman": rho_position,
            "position_vs_cycles_bootstrap_95ci": bootstrap_ci(positions, cycles),
            "position_vs_cycles_permutation_p_two_sided": permutation_p(
                positions, cycles, rho_position
            ),
            "circular_distance_vs_cycles_spearman": rho_distance,
            "circular_distance_vs_cycles_bootstrap_95ci": bootstrap_ci(
                circular_distance, cycles
            ),
            "circular_distance_vs_cycles_permutation_p_two_sided": permutation_p(
                circular_distance, cycles, rho_distance
            ),
        }
    )

result = {
    "schema": "mmat.scaled-single-position-timing-frames/v1",
    "status": "measurement_completed_analysis_not_independently_reviewed",
    "claim_scope": (
        "Complete all-secret-position one-bit c0 frames for the extracted original "
        "BIKE-MLThre reference decapsulation API at supported 256- and 512-bit "
        "parameters. These are local leakage/structure measurements, not a "
        "secret-key recovery or a demonstrated NGCC Low security defect."
    ),
    "frames": frames,
    "cross_key_observations": {
        "supported_256": (
            "Two distinct deterministic keys produced distinct key hashes. Their "
            "absolute median timing differed substantially, so only within-frame "
            "position ranks are compared; one repetition per position does not "
            "estimate repeatability."
        ),
        "supported_512": (
            "A complete 273-position frame was collected for the key-67 512-bit "
            "instance. A second key was not collected within this dispatch."
        ),
    },
    "causal_recovery_analysis": {
        "one_position_syndrome_invariant": (
            "In the cyclic polynomial ring, c0=x^i gives syndrome h0*x^i, a cyclic "
            "shift of h0. Its Hamming weight is exactly DV for every one-position "
            "c0, including non-support positions. Thus this frame cannot distinguish "
            "secret support membership through the syndrome-weight scalar."
        ),
        "implemented_ground_truth_confirmation": (
            "Every one-bit row in all three frames had syndrome_weight=DV, matching "
            "the cyclic-shift invariant."
        ),
        "pair_distance": (
            "The only completed pair-distance test remains the 128-bit exhaustive "
            "2,485-pair frame, whose Spearman association was -0.005864 with "
            "two-sided permutation p=0.769246. No pair-distance frame completed at "
            "256 or 512, so those parameter sets are not claimed either way."
        ),
        "query_estimate": (
            "No support-recovery query estimate is justified: scalar syndrome-weight "
            "leakage was observed at 128 random controls, while one-position masks "
            "are syndrome-weight invariant and measured pair distance showed no "
            "association. A recovery algorithm or additional implication is missing."
        ),
    },
    "controls": {
        "positive": (
            "The pre-existing 128-bit random-density controls showed syndrome-weight "
            "association; every key hash and frame shape was checked."
        ),
        "negative": (
            "All one-position rows have identical ground-truth syndrome weight, and "
            "the circular-position/distance tests provide within-class negative "
            "controls for spurious positional ordering."
        ),
        "optimized_build": "not collected",
        "instruction_or_branch_counters": (
            "not collected; hardware performance counters were unavailable"
        ),
    },
    "environment": {
        "kernel": "Linux 5.15.167.4-microsoft-standard-WSL2 x86_64",
        "cpu": "Intel Xeon w9-3495X; process pinned to CPU 0",
        "compiler": "gcc 13.3.0",
        "flags": (
            "-m64 -O3 -std=c99 -DNIST_RAND=1 "
            "-DBIKE_SECURITY_{128,256,512} -DBIKE_MLTHRE_ENABLED=1"
        ),
        "timer": "CLOCK_MONOTONIC_RAW nanoseconds plus serialized TSC",
    },
    "limitations": [
        "One repetition per exact input in the new 256/512 frames.",
        "Only two keys at 256 and one key at 512; position estimates are noisy.",
        "Absolute timings changed between runs and hosts/sessions; no cross-run speed comparison is valid.",
        "No optimized implementation, branch counter, or instruction counter result.",
        "No causal h0 recovery and therefore no NGCC Low security-impact claim.",
        "Independent evidence review has not accepted these measurements.",
    ],
}

with open("results_scaled_frames.json", "w") as handle:
    json.dump(result, handle, indent=2, sort_keys=True)
    handle.write("\n")

print(json.dumps(result, indent=2, sort_keys=True))
