#!/usr/bin/env bash
set -euo pipefail

root=native/ref128
out=native/triq_gap_harness

gcc -std=c99 -O2 -fno-strict-aliasing \
  -I "$root" \
  -I "$root/src/common" \
  -I "$root/src/common/triq-128" \
  -I "$root/src/ref" \
  -I "$root/src/ref/triq-128" \
  -o "$out" \
  native/triq_gap_harness.c \
  "$root/KEX_AlgorithmInstance.c" \
  "$root/drng.c" \
  "$root/auxfunc.c" \
  "$root/src/common/code.c" \
  "$root/src/common/crypto_memset.c" \
  "$root/src/common/fft.c" \
  "$root/src/common/kem.c" \
  "$root/src/common/symmetric.c" \
  "$root/src/ref/gf.c" \
  "$root/src/ref/gf2x.c" \
  "$root/src/ref/triq_pke.c" \
  "$root/src/ref/parsing.c" \
  "$root/src/ref/reed_muller.c" \
  "$root/src/ref/reed_solomon.c" \
  "$root/src/ref/vector.c"
