#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "$0")" && pwd)"
ref="$root/originals/submission/Implementations/Reference_Implementation"
mode="$ref/COMPASS-SIG-128"
out="$root/build"
log="$root/evidence/reproduce_highmode.log"

mkdir -p "$out" "$root/evidence"

for bits in 384 512; do
  for variant in exact sampler_only decomp_only; do
    flags=()
    case "$variant" in
      exact)
        flags+=("-DSPEC_CONFORMING_CHALLENGE")
        ;;
      sampler_only)
        flags+=("-DSPEC_CONFORMING_CHALLENGE" "-DSPEC_OMIT_DECOMP")
        ;;
      decomp_only)
        ;;
    esac

    cc -O2 -DCOMPASS_SIG_MODE="$bits" "${flags[@]}" \
      -I"$mode" -I"$ref" \
      -o "$out/spec_verify_${bits}_${variant}" \
      "$root/experiments/spec_verify_probe.c" \
      "$mode/sign.c" "$mode/packing.c" "$mode/polyvec.c" "$mode/poly.c" \
      "$mode/ntt.c" "$mode/reduce.c" "$mode/rounding.c" \
      "$mode/symmetric-shake.c" "$mode/drng.c" "$mode/auxfunc.c" \
      "$ref/fips202.c"
  done
done

for bits in 384 512; do
  for seed in 1 2 3; do
    evidence="$root/evidence/highmode_${bits}_seed${seed}"
    mkdir -p "$evidence"
    for variant in exact sampler_only decomp_only; do
      "$out/spec_verify_${bits}_${variant}" "$seed" 100 "$evidence"
    done
    sha256sum \
      "$evidence/message.bin" \
      "$evidence/public_key.bin" \
      "$evidence/signature.bin"
  done
done | tee "$log"
