#!/usr/bin/env bash
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
out="$here/model_trace"

for variant in stock128 l1json128; do
  root="$here/trace_$variant"
  inc="$root/bike_kem_ml"
  gcc -O2 -std=gnu11 -DVARIANT="\"$variant\"" -DSECURITY_BITS=128 \
    -DX86_64 -DUSE_NIST_RAND -DBIKE_MLTHRE_ENABLED=1 \
    -DBIKE_MLTHRE_DELTA_ENABLED=1 -DBIKE_MLTHRE_SAMPLING=1 \
    -I"$inc/include" -I"$inc/include/internal" -I"$inc/tests" \
    -I"$inc/tests/FromNIST" "$here/divergence_search_harness.c" \
    "$inc/tests/FromNIST/rng.c" "$root/build_kat_128/libbike_kem_ml.a" \
    -lcrypto -lm -o "$root/divergence_search_$variant"
done

for variant in stock128 l1json128; do
  root="$here/trace_$variant"
  taskset -c 2 "$root/divergence_search_$variant" \
    > "$out/${variant}_near_valid.csv"
done

python3 - "$out/stock128_near_valid.csv" \
  "$out/l1json128_near_valid.csv" "$out/near_valid_comparison.json" <<'PY'
import csv, json, sys

def read(path):
    with open(path, newline="") as f:
        lines = f.readlines()
    while lines and not lines[0].startswith("variant,"):
        lines.pop(0)
    return {
        (int(r["key"]), int(r["mutation"])): r
        for r in csv.DictReader(lines)
    }

stock = read(sys.argv[1])
l1 = read(sys.argv[2])
common = sorted(set(stock) & set(l1))
diffs = []
stock_success = l1_success = 0
for key, mutation in common:
    a, b = stock[(key, mutation)], l1[(key, mutation)]
    stock_success += int(a["match"] == "1")
    l1_success += int(b["match"] == "1")
    av = (a["ret"], a["match"], a["ss_fnv1a64"])
    bv = (b["ret"], b["match"], b["ss_fnv1a64"])
    if av != bv:
        diffs.append({
            "key": key,
            "mutation": mutation,
            "flips": int(a["flips"]),
            "ct_fnv1a64": a["ct_fnv1a64"],
            "stock": av,
            "l1json": bv,
        })
json.dump({
    "schema": "bike-mlthre-near-valid-divergence-search/v1",
    "common_inputs": len(common),
    "stock_successes": stock_success,
    "l1json_successes": l1_success,
    "terminal_outcome_differences": len(diffs),
    "differences": diffs,
    "limits": [
        "All ciphertexts are supported-length local 128-bit chosen inputs.",
        "A terminal difference would establish build-model interoperability divergence.",
        "No difference is not a proof that no such input exists.",
    ],
}, open(sys.argv[3], "w"), indent=2, sort_keys=True)
print(json.dumps({
    "common_inputs": len(common),
    "stock_successes": stock_success,
    "l1json_successes": l1_success,
    "terminal_outcome_differences": len(diffs),
}, indent=2))
PY
