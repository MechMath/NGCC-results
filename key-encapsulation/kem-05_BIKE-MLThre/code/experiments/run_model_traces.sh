#!/usr/bin/env bash
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
out="$here/model_trace"
mkdir -p "$out"

for variant in stock128 l1json128; do
  root="$here/trace_$variant"
  make -C "$root" clean
  make -C "$root" SECURITY=128 -j8
  inc="$root/bike_kem_ml"
  gcc -O2 -std=gnu11 -DVARIANT="\"$variant\"" -DSECURITY_BITS=128 \
    -DX86_64 -DUSE_NIST_RAND -DBIKE_MLTHRE_ENABLED=1 \
    -DBIKE_MLTHRE_DELTA_ENABLED=1 -DBIKE_MLTHRE_SAMPLING=1 \
    -I"$inc/include" -I"$inc/include/internal" -I"$inc/tests" \
    -I"$inc/tests/FromNIST" "$here/model_trace_harness.c" \
    "$inc/tests/FromNIST/rng.c" "$root/build_kat_128/libbike_kem_ml.a" \
    -lcrypto -lm -o "$root/model_trace_$variant"
done

for round in 1 2; do
  for variant in stock128 l1json128; do
    root="$here/trace_$variant"
    prefix="$out/${variant}_r${round}"
    BIKE_MLTHRE_CANDIDATES_CSV="${prefix}_candidates.csv" \
      taskset -c 2 "$root/model_trace_$variant" > "${prefix}_outcomes.csv"
  done
done

python3 "$here/analyze_model_traces.py" \
  "$out/stock128_r1_candidates.csv" "$out/l1json128_r1_candidates.csv" \
  "$out/stock128_r1_outcomes.csv" "$out/l1json128_r1_outcomes.csv" \
  > "$out/comparison_r1.json"

python3 "$here/analyze_model_traces.py" \
  "$out/stock128_r1_candidates.csv" "$out/stock128_r2_candidates.csv" \
  "$out/stock128_r1_outcomes.csv" "$out/stock128_r2_outcomes.csv" \
  > "$out/stock_repeat_control.json"

python3 "$here/analyze_model_traces.py" \
  "$out/l1json128_r1_candidates.csv" "$out/l1json128_r2_candidates.csv" \
  "$out/l1json128_r1_outcomes.csv" "$out/l1json128_r2_outcomes.csv" \
  > "$out/l1json_repeat_control.json"
