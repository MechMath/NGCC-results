#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
darts="$root/original/submission/Implementations/Reference_Implementation/DARTS128"

gcc -O3 -march=native -mtune=native -std=gnu99 -fcommon \
  -Wall -Wextra -Wpedantic -I "$darts" \
  -o "$root/experiments/malleability_repro" \
  "$root/experiments/malleability_repro.c" \
  "$darts/sign.c" "$darts/packing.c" "$darts/polyvec.c" "$darts/poly.c" \
  "$darts/ntt.c" "$darts/reduce.c" "$darts/sampler.c" "$darts/encoding.c" \
  "$darts/polyfix.c" "$darts/polymat.c" "$darts/fft.c" "$darts/fixpoint.c" \
  "$darts/symmetric.c" "$darts/drng.c" "$darts/auxfunc.c" \
  "$darts/SIG_AlgorithmInstance.c" -lm

"$root/experiments/malleability_repro" | tee "$root/experiments/malleability_repro.txt"

sha256sum \
  "$root/experiments/repro.pk" \
  "$root/experiments/repro.sig" \
  "$root/experiments/repro.mutated.sig" \
  "$root/experiments/repro.msg" \
  "$root/experiments/malleability_repro.c" \
  "$root/experiments/malleability_repro"
