#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "$0")" && pwd)"
bra="$root/source/Implementations/Optimized_Implementation/BRA-128"

gcc -O2 -g -march=x86-64 -mavx2 -mtune=native \
  -fomit-frame-pointer -mpclmul -msse4.2 -maes -std=c99 \
  -Wpedantic -Wall -Wextra \
  -I "$bra" -I "$bra/src" -I "$bra/src/rbc-67" \
  -I "$bra/lib/random_source" -I "$bra/lib/XKCP" \
  -I "$bra/lib/XKCP/avx2" -I "$bra/lib/wrapper" \
  "$root/oob_api_harness.c" \
  "$bra/bin/build/rbc_elt.o" "$bra/bin/build/rbc_vec.o" \
  "$bra/bin/build/rbc_poly.o" "$bra/bin/build/rbc_qre.o" \
  "$bra/bin/build/rbc_vspace.o" "$bra/bin/build/parsing.o" \
  "$bra/bin/build/qpoly.o" "$bra/bin/build/augmented_gabidulin.o" \
  "$bra/bin/build/bra.o" "$bra/bin/build/kem.o" \
  "$bra/bin/build/KEM_BRA-128.o" "$bra/bin/build/drng.o" \
  "$bra/bin/build/auxfunc.o" "$bra/bin/build/random_source.o" \
  "$bra/bin/build/KeccakHash.o" "$bra/bin/build/KeccakHashtimes4.o" \
  "$bra/bin/build/KeccakSponge.o" "$bra/bin/build/KeccakSpongetimes4.o" \
  "$bra/bin/build/SimpleFIPS202.o" "$bra/bin/build/KeccakP-1600-AVX2.o" \
  "$bra/bin/build/KeccakP-1600-times4-SIMD256.o" \
  -o "$root/oob_api_harness_plain"
