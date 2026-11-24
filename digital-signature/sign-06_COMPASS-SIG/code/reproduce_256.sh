#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "$0")" && pwd)"
ref="$root/originals/submission/Implementations/Reference_Implementation"
mode="$ref/COMPASS-SIG-128"
out="$root/build"
log="$root/evidence/reproduce_256.log"

mkdir -p "$out" "$root/evidence"

cc -O2 -DCOMPASS_SIG_MODE=256 \
  -I"$mode" -I"$ref" \
  -o "$out/spec_verify_256" \
  "$root/experiments/spec_verify_probe.c" \
  "$mode/sign.c" "$mode/packing.c" "$mode/polyvec.c" "$mode/poly.c" \
  "$mode/ntt.c" "$mode/reduce.c" "$mode/rounding.c" \
  "$mode/symmetric-shake.c" "$mode/drng.c" "$mode/auxfunc.c" \
  "$ref/fips202.c"

for seed in 1 2 3; do
  evidence="$root/evidence/compass_sig_256_seed${seed}"
  mkdir -p "$evidence"
  "$out/spec_verify_256" "$seed" 1000 "$evidence"
  sha256sum \
    "$evidence/message.bin" \
    "$evidence/public_key.bin" \
    "$evidence/signature.bin"
done | tee "$log"
