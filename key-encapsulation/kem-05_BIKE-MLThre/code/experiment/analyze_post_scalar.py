#!/usr/bin/env python3
import csv
import collections
import json
import math
import random
import statistics

PRIOR = "experiment/multikey_rows.csv"
VALID = "experiment/post_scalar_validation_rows.csv"
OUT = "experiment/post_scalar_validation_results.json"
RNG = random.Random(0x5CA1A7)

def mean(xs):
    return sum(xs) / len(xs)

def ranks(xs):
    order = sorted(range(len(xs)), key=xs.__getitem__)
    out = [0.0] * len(xs)
    i = 0
    while i < len(xs):
        j = i + 1
        while j < len(xs) and xs[order[j]] == xs[order[i]]:
            j += 1
        r = (i + j - 1) / 2.0 + 1.0
        for p in order[i:j]:
            out[p] = r
        i = j
    return out

def pearson(xs, ys):
    if len(xs) < 2:
        return None
    mx, my = mean(xs), mean(ys)
    dx = sum((x - mx) ** 2 for x in xs)
    dy = sum((y - my) ** 2 for y in ys)
    if dx == 0 or dy == 0:
        return None
    return sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / math.sqrt(dx * dy)

def spearman(xs, ys):
    return pearson(ranks(xs), ranks(ys))

def percentile(xs, q):
    xs = sorted(xs)
    return xs[round((len(xs) - 1) * q)]

def load(path):
    rows = list(csv.DictReader(open(path, newline="")))
    by_sample = collections.defaultdict(list)
    for row in rows:
        by_sample[int(row["sample_id"])].append(row)
    samples = []
    for sample_id, rs in by_sample.items():
        first = rs[0]
        samples.append({
            "sample_id": sample_id,
            "key_id": int(first["key_id"]),
            "stratum": int(first["stratum"]),
            "mask_id": int(first["mask_id"]),
            "c0_weight": int(first["c0_weight"]),
            "syndrome_weight": int(first["syndrome_weight"]),
            "cycles": [float(r["cycles"]) for r in rs],
            "statuses": [int(r["dec_status"]) for r in rs],
        })
    samples.sort(key=lambda s: s["sample_id"])
    return samples

prior = load(PRIOR)
valid = load(VALID)
if len(prior) != 1008 or len(valid) != 1008:
    raise SystemExit("expected 1008 masks in each run")
if [s["sample_id"] for s in prior] != [s["sample_id"] for s in valid]:
    raise SystemExit("sample order mismatch")
for a, b in zip(prior, valid):
    for key in ("key_id", "stratum", "mask_id", "c0_weight", "syndrome_weight"):
        if a[key] != b[key]:
            raise SystemExit(f"sample metadata mismatch in {key}")
if not all(x == 0 for s in prior + valid for x in s["statuses"]):
    raise SystemExit("nonzero decapsulation status")

for s in prior:
    s["prior_median_log"] = math.log(statistics.median(s["cycles"]))
for s in valid:
    s["valid_median_log"] = math.log(statistics.median(s["cycles"]))
    s["valid_half_a_log"] = math.log(statistics.median(s["cycles"][:4]))
    s["valid_half_b_log"] = math.log(statistics.median(s["cycles"][4:]))

cells = collections.defaultdict(list)
for a, b in zip(prior, valid):
    b["prior_median_log"] = a["prior_median_log"]
    cells[(b["key_id"], b["stratum"])].append(b)

def ols_residual(xs, ys):
    mx, my = mean(xs), mean(ys)
    den = sum((x - mx) ** 2 for x in xs)
    if den == 0:
        return [y - my for y in ys]
    slope = sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / den
    return [y - (my + slope * (x - mx)) for x, y in zip(xs, ys)]

def residual_vectors(cell_list, xname, yname):
    xs, ys = [], []
    for cell in cell_list:
        weights = [s["syndrome_weight"] for s in cell]
        xs.extend(ols_residual(weights, [s[xname] for s in cell]))
        ys.extend(ols_residual(weights, [s[yname] for s in cell]))
    return xs, ys

def pooled_residual(cell_list):
    xs, ys = residual_vectors(cell_list, "prior_median_log", "valid_median_log")
    return pearson(xs, ys)

def validation_split_half(cell_list):
    xs, ys = residual_vectors(cell_list, "valid_half_a_log", "valid_half_b_log")
    return pearson(xs, ys)

all_cells = [cells[(k, i)] for k in range(3) for i in range(7)]
observed = pooled_residual(all_cells)

boot = []
for _ in range(2000):
    sample_cells = []
    for cell in all_cells:
        sample_cells.append([cell[RNG.randrange(len(cell))] for _ in cell])
    value = pooled_residual(sample_cells)
    if value is not None:
        boot.append(value)
boot.sort()

null = []
for _ in range(10000):
    permuted = []
    for cell in all_cells:
        permuted.append([dict(s) for s in cell])
    for cell in permuted:
        ys = [s["valid_median_log"] for s in cell]
        RNG.shuffle(ys)
        for s, y in zip(cell, ys):
            s["valid_median_log"] = y
    value = pooled_residual(permuted)
    if value is not None:
        null.append(value)
p = (sum(abs(v) >= abs(observed) for v in null) + 1) / (len(null) + 1)

key_results = []
for k in range(3):
    kc = [cells[(k, i)] for i in range(7)]
    x, y = residual_vectors(kc, "prior_median_log", "valid_median_log")
    key_results.append({
        "key_id": k,
        "residual_pearson": pearson(x, y),
        "residual_spearman": spearman(x, y),
        "validation_split_half_pearson": validation_split_half(kc),
    })

x, y = residual_vectors(all_cells, "prior_median_log", "valid_median_log")
result = {
    "schema": "mmat.post-scalar-timing-validation-result/v1",
    "status": "fresh_validation_measurement_completed_not_independently_reviewed",
    "prior_repetitions": 3,
    "validation_repetitions": 9,
    "masks": len(valid),
    "decapsulations_validation": len(valid) * 9,
    "all_status_zero": True,
    "pooled": {
        "residual_pearson": observed,
        "residual_spearman": spearman(x, y),
        "bootstrap_95ci": [percentile(boot, 0.025), percentile(boot, 0.975)],
        "within_cell_label_permutation_p_two_sided": p,
        "validation_split_half_pearson": validation_split_half(all_cells),
    },
    "per_key": key_results,
    "support_gate_met": bool(
        min(boot) > 0 and observed > 0 and
        validation_split_half(all_cells) is not None and
        validation_split_half(all_cells) > 0
    ),
    "claim_boundary": "Reproducible mask-specific timing after syndrome-weight regression would show additional secret-dependent structure only. It is not bit recovery, h0 recovery, remote attack, or NGCC-Low impact."
}
with open(OUT, "w") as f:
    json.dump(result, f, indent=2)
    f.write("\n")
print(json.dumps(result, indent=2))
