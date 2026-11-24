#!/usr/bin/env python3
import collections
import csv
import json
import math
import random
import statistics

ROWS = "experiment/timing_rows_128.csv"
META = "experiment/timing_meta_128.json"
OUT = "results.json"
RNG = random.Random(0x12851)

KIND_NAMES = {
    0: "zero",
    1: "one_secret_position",
    2: "two_secret_positions",
    3: "valid_encapsulation",
    4: "random_sparse",
    5: "random_dense",
}


def percentile(values, q):
    values = sorted(values)
    return values[round((len(values) - 1) * q)]


def mean(values):
    return sum(values) / len(values)


def pearson(xs, ys):
    mx, my = mean(xs), mean(ys)
    num = sum((x - mx) * (y - my) for x, y in zip(xs, ys))
    dx = sum((x - mx) ** 2 for x in xs)
    dy = sum((y - my) ** 2 for y in ys)
    return num / math.sqrt(dx * dy) if dx and dy else 0.0


def rankdata(xs):
    order = sorted(range(len(xs)), key=xs.__getitem__)
    ranks = [0.0] * len(xs)
    i = 0
    while i < len(xs):
        j = i + 1
        while j < len(xs) and xs[order[j]] == xs[order[i]]:
            j += 1
        rank = (i + j - 1) / 2.0 + 1.0
        for k in range(i, j):
            ranks[order[k]] = rank
        i = j
    return ranks


def spearman(xs, ys):
    return pearson(rankdata(xs), rankdata(ys))


def bootstrap_ci(xs, ys, fn, n=2000):
    values = []
    size = len(xs)
    for _ in range(n):
        idx = [RNG.randrange(size) for _ in range(size)]
        values.append(fn([xs[i] for i in idx], [ys[i] for i in idx]))
    values.sort()
    return [values[int(0.025 * (n - 1))], values[int(0.975 * (n - 1))]]


def permutation_p(xs, ys, observed, n=5000):
    ys = list(ys)
    count = 0
    for _ in range(n):
        RNG.shuffle(ys)
        if abs(spearman(xs, ys)) >= abs(observed):
            count += 1
    return (count + 1) / (n + 1)


def auc_less(fast, slow):
    return sum((a < b) + 0.5 * (a == b) for a in fast for b in slow) / (
        len(fast) * len(slow)
    )


def bootstrap_auc_less(fast, slow, n=1000):
    values = []
    for _ in range(n):
        aa = [fast[RNG.randrange(len(fast))] for _ in range(len(fast))]
        bb = [slow[RNG.randrange(len(slow))] for _ in range(len(slow))]
        values.append(auc_less(aa, bb))
    values.sort()
    return [values[25], values[974]]


with open(ROWS, newline="") as f:
    raw = list(csv.DictReader(f))

by_id = collections.defaultdict(list)
for row in raw:
    by_id[int(row["sample_id"])].append(row)

samples = []
for sample_id, rows in by_id.items():
    first = dict(rows[0])
    cycles = [float(r["cycles"]) for r in rows]
    ns = [float(r["ns"]) for r in rows]
    first["cycle_min"] = min(cycles)
    first["cycle_median"] = statistics.median(cycles)
    first["cycle_trim3"] = mean(sorted(cycles)[:3])
    first["ns_median"] = statistics.median(ns)
    first["rep_cv"] = statistics.pstdev(cycles) / mean(cycles)
    first["kind"] = int(first["kind"])
    first["syndrome_weight"] = int(first["syndrome_weight"])
    first["autocorr_1"] = int(first["autocorr_1"])
    first["autocorr_2"] = int(first["autocorr_2"])
    first["distance"] = int(first["distance"])
    samples.append(first)

classes = {}
for kind, name in KIND_NAMES.items():
    selected = [s for s in samples if s["kind"] == kind]
    med = sorted(s["cycle_median"] for s in selected)
    mins = sorted(s["cycle_min"] for s in selected)
    classes[name] = {
        "samples": len(selected),
        "syndrome_weight_min": min(s["syndrome_weight"] for s in selected),
        "syndrome_weight_max": max(s["syndrome_weight"] for s in selected),
        "cycles_median": statistics.median(med),
        "cycles_min_of_sample_medians": min(med),
        "cycles_max_of_sample_medians": max(med),
        "cycles_median_min_of_7": statistics.median(mins),
        "rep_cv_median": statistics.median(s["rep_cv"] for s in selected),
    }

pairs = [s for s in samples if s["kind"] == 2]
valid = [s for s in samples if s["kind"] == 3]
random_classes = [s for s in samples if s["kind"] in (4, 5)]

pair_x = [s["distance"] for s in pairs]
pair_y = [s["cycle_trim3"] for s in pairs]
pair_rho = spearman(pair_x, pair_y)

sw_x = [s["syndrome_weight"] for s in random_classes]
sw_y = [s["cycle_trim3"] for s in random_classes]
sw_rho = spearman(sw_x, sw_y)

pair_times = [s["cycle_median"] for s in pairs]
valid_times = [s["cycle_median"] for s in valid]

analysis = {
    "schema": "mmat.local-timing-experiment/v1",
    "status": "measurement_completed_analysis_not_independently_reviewed",
    "claim_scope": (
        "Timing distributions of the extracted original BIKE-MLThre reference "
        "decapsulation path for the 128-bit supported parameter set on one "
        "fixed deterministic key and this host. This is leakage/structure evidence, "
        "not a demonstrated secret-key recovery or a security-level claim."
    ),
    "contamination": "none observed; only the authorized submission ZIP and PDF were fetched",
    "input": {
        "zip_sha256": "3a5d97532003786374b68b39779cff4e4938f593fef9596f171652c6ff593917",
        "spec_sha256": "f3d1145190beef22e065bdefaf32a48a26ef03a4822a4b3d45e0703ffb871479",
        "reference_decode_c_sha256": "95f698e76873a38291a600a00b7133cbc3e41e8f52501f1054796e8be14e6c70",
        "reference_kem_c_sha256": "694d6ce6ac68a025760b08dd1333633fb204bc327077ddd9a8db95cb54a02092",
        "timing_bench_c_sha256": "83d1152967cf0969535bc475b0ed5417929ac37337ed2efe7f1386b6f7138511",
    },
    "environment": {
        "kernel": "Linux 5.15.167.4-microsoft-standard-WSL2 x86_64",
        "cpu": "Intel Xeon w9-3495X, pinned to CPU 0",
        "compiler": "gcc 13.3.0",
        "flags": "-m64 -O3 -std=c99 -DNIST_RAND=1 -DBIKE_SECURITY_128 -DBIKE_MLTHRE_ENABLED=1",
        "timer": "CLOCK_MONOTONIC_RAW nanoseconds plus serialized TSC",
    },
    "protocol": {
        "key_seed": "42 repeated 48 bytes",
        "repetitions_per_exact_input": 7,
        "measurement_order": "all sample ids shuffled independently in each repetition",
        "total_decapsulations_timed": len(raw),
        "timed_call": "crypto_kem_dec(ss, chosen_ct, fixed_sk)",
        "attacker_model": (
            "offline local timing of a supported decapsulation API; c0 is chosen "
            "by the caller; secret h0 is used only by the evaluator to construct "
            "diagnostic masks and compute ground truth"
        ),
        "controls": (
            "zero syndrome; all 71 one-position secret masks; all 2,485 two-position "
            "secret masks; 64 genuine encapsulations with matching shared secret; "
            "128 random-sparse and 128 random-dense masks"
        ),
    },
    "classes": classes,
    "genuine_encapsulation_control": {
        "timed_rows": len(valid) * 7,
        "matching_shared_secret_rows": sum(r["valid_ss_match"] == "1" for r in raw if int(r["kind"]) == 3),
    },
    "two_position_distance_test": {
        "n": len(pairs),
        "spearman_distance_vs_trimmed_cycles": pair_rho,
        "bootstrap_95ci": bootstrap_ci(pair_x, pair_y, spearman),
        "permutation_p_two_sided": permutation_p(pair_x, pair_y, pair_rho),
        "interpretation": (
            "No practical rank association was observed. This run supplies no "
            "pair-distance-based support-recovery algorithm."
        ),
    },
    "syndrome_weight_test": {
        "population": "128 random-sparse plus 128 random-dense chosen c0 controls",
        "n": len(random_classes),
        "syndrome_weight_range": [min(sw_x), max(sw_x)],
        "spearman_weight_vs_trimmed_cycles": sw_rho,
        "bootstrap_95ci": bootstrap_ci(sw_x, sw_y, spearman),
        "permutation_p_two_sided": permutation_p(sw_x, sw_y, sw_rho),
        "interpretation": (
            "Positive-rank association in this single-key exploratory sample. "
            "It is not independent validation and not directly a secret-key oracle."
        ),
    },
    "valid_vs_two_position_control": {
        "auc_probability_pair_mask_faster": auc_less(pair_times, valid_times),
        "bootstrap_95ci": bootstrap_auc_less(pair_times, valid_times),
        "interpretation": (
            "The public c0 population is strongly separable, but the classes are "
            "also distinguishable from public c0 density. This is not by itself "
            "evidence of a secret-dependent timing oracle."
        ),
    },
    "limitations": [
        "Only the 128-bit supported parameter set completed within this dispatch window.",
        "One deterministic key was measured; this does not establish population or key diversity.",
        "Only seven repetitions per exact input were used; WSL2 scheduling noise is substantial.",
        "No branch or instruction counters were collected; timing is end-to-end wall/TSC time.",
        "No independent evidence review or verifier verdict has yet accepted this measurement.",
        "A timing correlation alone is not a security defect and no h0 recovery was demonstrated.",
    ],
}

with open(OUT, "w") as f:
    json.dump(analysis, f, indent=2, sort_keys=True)
    f.write("\n")

print(json.dumps({
    "classes": classes,
    "pair_distance": analysis["two_position_distance_test"],
    "syndrome_weight": analysis["syndrome_weight_test"],
    "valid_vs_pair": analysis["valid_vs_two_position_control"],
}, indent=2, sort_keys=True))
