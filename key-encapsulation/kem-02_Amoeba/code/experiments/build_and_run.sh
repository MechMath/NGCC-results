#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
SRC="$ROOT/submission/Implementations/Reference_Implementation/Amoeba-576/src"

cd "$ROOT"

printf '%s  %s\n' \
  719c438a30cccd72c9d83da4b5150fee0c55351f2c13e7a66fd61bf653ca5c24 \
  Amoeba.zip | sha256sum -c -
printf '%s  %s\n' \
  ffca61c5470298f3a173b76a8ead43299a04d990b0bbb913397f910285d4d247 \
  kem-02-spec.pdf | sha256sum -c -

gcc -std=c11 -O3 -march=native -fPIC -w -DSECURITY_LEVEL=128 \
  -I"$SRC/api" -I"$SRC/backend" -I"$SRC/symmetric" \
  experiments/amoeba576_control.c \
  "$SRC/symmetric/auxfunc.c" \
  "$SRC/symmetric/drng.c" \
  "$SRC/backend/ccakem.c" \
  "$SRC/backend/cpapke.c" \
  "$SRC/backend/hamming.c" \
  "$SRC/backend/ntt_2s3t.c" \
  "$SRC/backend/poly.c" \
  "$SRC/backend/randombytes.c" \
  "$SRC/backend/zetas.c" \
  "$SRC/api/KEM_AlgorithmInstance.c" \
  -o experiments/amoeba576_control

./experiments/amoeba576_control | tee experiments/run.stdout

sha256sum output/* | sort > experiments/output.sha256
find submission/Implementations/Reference_Implementation/Amoeba-576 \
  -type f -print0 | sort -z | xargs -0 sha256sum \
  > experiments/source.sha256

set +e
cmp -l output/ct.bin output/ct_pad_bit.bin \
  > experiments/diff_ct_to_pad_bit.txt
cmp -l output/ct.bin output/ct_checked_byte.bin \
  > experiments/diff_ct_to_checked_byte.txt
cmp -l output/ct_pad_bit.bin output/reencrypted_original.bin \
  > experiments/diff_pad_bit_to_reencrypt.txt
cmp -l output/ct_checked_byte.bin output/reencrypted_original.bin \
  > experiments/diff_checked_byte_to_reencrypt.txt
exit 0
