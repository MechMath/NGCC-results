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
    -DBIKE_L7_REFERENCE_DECODER=1 -DBIKE_L7_DYNAMIC_THRESHOLD=1 \
    -DBIKE_L7_EMPIRICAL_THRESHOLD=0 -DUSE_API_PKC_AUX=1 \
    -DSTANDALONE_IMPL=1 \
    -I"$inc/include" -I"$inc/include/internal" \
    -I"$inc/src/third_party_src" -I"$inc/tests" \
    -I"$inc/tests/FromNIST" "$here/valid_ciphertext_search_harness.c" \
    "$inc/tests/FromNIST/rng.c" "$root/build_kat_128/libbike_kem_ml.a" \
    -lcrypto -lm -o "$root/valid_search_$variant"
done

for variant in stock128 l1json128; do
  root="$here/trace_$variant"
  taskset -c 2 "$root/valid_search_$variant" \
    > "$out/${variant}_valid_inputs.csv"
done

python3 - "$out/stock128_valid_inputs.csv" \
  "$out/l1json128_valid_inputs.csv" "$out/valid_input_comparison.json" <<'PY'
import csv, json, sys

def read(path):
    with open(path, newline="") as f:
        lines = f.readlines()
    while lines and not lines[0].startswith("variant,"):
        lines.pop(0)
    return {
        (int(r["key"]), int(r["message"])): r
        for r in csv.DictReader(lines)
    }

stock = read(sys.argv[1])
l1 = read(sys.argv[2])
common = sorted(set(stock) & set(l1))
diffs = []
stock_success = l1_success = 0
for key, message in common:
    a, b = stock[(key, message)], l1[(key, message)]
    stock_success += int(a["match"] == "1")
    l1_success += int(b["match"] == "1")
    av = (a["ret"], a["match"], a["ss_fnv1a64"])
    bv = (b["ret"], b["match"], b["ss_fnv1a64"])
    if av != bv:
        diffs.append({
            "key": key,
            "message": message,
            "ct_fnv1a64": a["ct_fnv1a64"],
            "m_fnv1a64": a["m_fnv1a64"],
            "stock": av,
            "l1json": bv,
        })
json.dump({
    "schema": "bike-mlthre-valid-input-divergence-search/v1",
    "common_inputs": len(common),
    "stock_successes": stock_success,
    "l1json_successes": l1_success,
    "terminal_outcome_differences": len(diffs),
    "differences": diffs,
    "limits": [
        "Messages are public deterministic values and ciphertexts are constructed from the original supported encryption equation.",
        "A terminal difference establishes same-object build interoperability divergence.",
        "No difference is a bounded null result, not a universal equivalence proof.",
    ],
}, open(sys.argv[3], "w"), indent=2, sort_keys=True)
print(json.dumps({
    "common_inputs": len(common),
    "stock_successes": stock_success,
    "l1json_successes": l1_success,
    "terminal_outcome_differences": len(diffs),
}, indent=2))
PY
