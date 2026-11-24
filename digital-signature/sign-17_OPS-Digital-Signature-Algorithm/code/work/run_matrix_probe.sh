#!/bin/sh
set -eu

ROOT=/home/mmat/mmat-preview/runs/ngcc-sign-17-ds01/insights/8f27682b7bdb09cf/authors/8fbf061548634529/native/work
OUT=/home/mmat/mmat-preview/runs/ngcc-sign-17-ds01/run/slots/bbd277730bd94d42/work
REF="$ROOT/original-package/Implementations and Test_Vectors/Implementations/Reference_Implementation/OPSsig-128"
AVX="$ROOT/original-package/Implementations and Test_Vectors/Implementations/Optimized_Implementation/OPSsig-128-avx2"

cc -O2 -std=c99 -Wall -Wextra -I"$REF" -o "$OUT/matrix_probe_ref" \
  "$OUT/matrix_probe.c" "$REF"/sign.c "$REF"/mult.c "$REF"/packing.c \
  "$REF"/polyvec.c "$REF"/poly.c "$REF"/ntt.c "$REF"/reduce.c \
  "$REF"/rounding.c "$REF"/auxfunc.c "$REF"/drng.c

cc -O3 -march=x86-64 -mavx2 -mtune=native -flto -fomit-frame-pointer \
  -std=c99 -Wall -Wextra -I"$AVX" -o "$OUT/matrix_probe_avx" \
  "$OUT/matrix_probe.c" "$AVX"/sign.c "$AVX"/packing.c "$AVX"/polyvec.c \
  "$AVX"/poly.c "$AVX"/rejsample.c "$AVX"/ntt.c "$AVX"/pointwise.S \
  "$AVX"/consts.c "$AVX"/reduce.c "$AVX"/rounding.c "$AVX"/sm3x4.c \
  "$AVX"/auxfunc.c "$AVX"/drng.c
