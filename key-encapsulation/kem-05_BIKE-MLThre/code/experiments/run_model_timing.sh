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
    -I"$inc/tests/FromNIST" "$here/model_timing_harness.c" \
    "$inc/tests/FromNIST/rng.c" "$root/build_kat_128/libbike_kem_ml.a" \
    -lcrypto -lm -o "$root/model_timing_$variant"
done

for round in 1 2; do
  for variant in stock128 l1json128; do
    root="$here/trace_$variant"
    taskset -c 2 "$root/model_timing_$variant" \
      > "$out/${variant}_timing_r${round}.csv"
  done
done

python3 "$here/analyze_model_timing.py" \
  "$out/stock128_timing_r1.csv" "$out/l1json128_timing_r1.csv" \
  > "$out/timing_comparison_r1.json"

python3 "$here/analyze_model_timing.py" \
  "$out/stock128_timing_r2.csv" "$out/l1json128_timing_r2.csv" \
  > "$out/timing_comparison_r2.json"
