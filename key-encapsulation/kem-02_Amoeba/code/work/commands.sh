#!/bin/bash
set -euo pipefail
SRC=work/submission/extracted/Implementations/Reference_Implementation/Amoeba-576/src

gcc -O2 -w -Dinline='static inline' -DSECURITY_LEVEL=128 \
  -I"$SRC/api" -I"$SRC/backend" -I"$SRC/symmetric" \
  work/amoeba_padding_test.c \
  "$SRC"/api/KEM_AlgorithmInstance.c \
  "$SRC"/backend/ccakem.c \
  "$SRC"/backend/cpapke.c \
  "$SRC"/backend/hamming.c \
  "$SRC"/backend/ntt_2s3t.c \
  "$SRC"/backend/poly.c \
  "$SRC"/backend/randombytes.c \
  "$SRC"/backend/zetas.c \
  "$SRC"/symmetric/auxfunc.c \
  "$SRC"/symmetric/drng.c \
  -o work/amoeba_padding_test

./work/amoeba_padding_test > work/amoeba_padding_test.stdout \
  2> work/amoeba_padding_test.stderr

# Control: exact submitted source except cmp compares every byte.
gcc -O2 -w -Dinline='static inline' -DSECURITY_LEVEL=128 \
  -I"$SRC/api" -I"$SRC/backend" -I"$SRC/symmetric" \
  work/amoeba_padding_test.c \
  "$SRC"/api/KEM_AlgorithmInstance.c \
  work/spec_compare_src/ccakem_spec_compare.c \
  "$SRC"/backend/cpapke.c \
  "$SRC"/backend/hamming.c \
  "$SRC"/backend/ntt_2s3t.c \
  "$SRC"/backend/poly.c \
  "$SRC"/backend/randombytes.c \
  "$SRC"/backend/zetas.c \
  "$SRC"/symmetric/auxfunc.c \
  "$SRC"/symmetric/drng.c \
  -o work/amoeba_padding_test_spec_compare_patched

./work/amoeba_padding_test_spec_compare_patched \
  > work/amoeba_padding_test_spec_compare_patched.stdout \
  2> work/amoeba_padding_test_spec_compare_patched.stderr
