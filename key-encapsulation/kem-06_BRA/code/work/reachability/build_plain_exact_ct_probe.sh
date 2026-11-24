#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "$0")" && pwd)"
bra="$root/../oob/source/Implementations/Optimized_Implementation/BRA-128"
build="$bra/bin/build"
plain_flags='-O3 -march=x86-64 -mavx2 -mtune=native -flto -fomit-frame-pointer -mpclmul -msse4.2 -maes -std=c99 -Wpedantic -Wall -Wextra'

make -C "$bra" clean
make -C "$bra" BRA-128-kat CC=gcc C_FLAGS="$plain_flags"

gcc -O3 -march=x86-64 -mavx2 -mtune=native \
  -flto -fomit-frame-pointer -mpclmul -msse4.2 -maes -std=c99 \
  -Wpedantic -Wall -Wextra \
  -I "$bra" -I "$bra/src" -I "$bra/src/rbc-67" \
  -I "$bra/lib/random_source" -I "$bra/lib/XKCP" \
  -I "$bra/lib/XKCP/avx2" -I "$bra/lib/wrapper" \
  "$root/exact_ct_probe.c" \
  "$build/rbc_elt.o" "$build/rbc_vec.o" "$build/rbc_poly.o" \
  "$build/rbc_qre.o" "$build/rbc_vspace.o" "$build/parsing.o" \
  "$build/qpoly.o" "$build/augmented_gabidulin.o" "$build/bra.o" \
  "$build/kem.o" "$build/KEM_BRA-128.o" "$build/drng.o" \
  "$build/auxfunc.o" "$build/random_source.o" "$build/KeccakHash.o" \
  "$build/KeccakHashtimes4.o" "$build/KeccakSponge.o" \
  "$build/KeccakSpongetimes4.o" "$build/SimpleFIPS202.o" \
  "$build/KeccakP-1600-AVX2.o" "$build/KeccakP-1600-times4-SIMD256.o" \
  -o "$root/exact_ct_probe_plain"
