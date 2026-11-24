#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "$0")" && pwd)"
out="$root/build"
log="$root/evidence/reproduce_challenge.log"

mkdir -p "$out"

for impl in Reference_Implementation Optimized_Implementation; do
  ref="$root/originals/submission/Implementations/$impl"
  for mode in 384 512; do
    dir="$ref/COMPASS-SIG-128"
    cc -O2 -DCOMPASS_SIG_MODE="$mode" \
      -I"$dir" -I"$ref" \
      -o "$out/challenge_${impl}_${mode}" \
      "$root/experiments/challenge_probe.c" \
      "$dir/sign.c" "$dir/packing.c" "$dir/polyvec.c" "$dir/poly.c" \
      "$dir/ntt.c" "$dir/reduce.c" "$dir/rounding.c" \
      "$dir/symmetric-shake.c" "$dir/drng.c" "$dir/auxfunc.c" \
      "$ref/fips202.c"
    printf "implementation=%s " "$impl"
    "$out/challenge_${impl}_${mode}" 10000
  done
done | tee "$log"
