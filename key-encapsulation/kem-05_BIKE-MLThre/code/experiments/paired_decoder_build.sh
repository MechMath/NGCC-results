#!/bin/bash
set -euo pipefail

root=$(cd "$(dirname "$0")" && pwd)
slot=$(cd "$root/.." && pwd)

for variant in stock_log supplied_log; do
  dir="$root/optimization128_$variant"
  make -C "$dir" clean
  make -C "$dir" SECURITY=128 -j8
  inc="$dir/bike_kem_ml"
  gcc -O2 -std=gnu11 -DVARIANT="\"opt_$variant\"" -DSECURITY_BITS=128 -DX86_64 \
    -I"$inc/include" -I"$inc/include/internal" -I"$inc/tests" \
    -I"$inc/tests/FromNIST" "$root/paired_decoder_harness.c" \
    "$inc/tests/FromNIST/rng.c" \
    "$dir/build_kat_128/libbike_kem_ml.a" -lcrypto -lm \
    -o "$dir/paired_decoder_$variant"
  gcc -O2 -std=gnu11 -DVARIANT="\"opt_$variant\"" -DSECURITY_BITS=128 -DX86_64 \
    -I"$inc/include" -I"$inc/include/internal" -I"$inc/tests" \
    -I"$inc/tests/FromNIST" "$root/boundary_search_harness.c" \
    "$inc/tests/FromNIST/rng.c" \
    "$dir/build_kat_128/libbike_kem_ml.a" -lcrypto -lm \
    -o "$dir/boundary_search_$variant"
done
