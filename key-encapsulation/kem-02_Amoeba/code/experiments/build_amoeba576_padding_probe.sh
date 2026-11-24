#!/usr/bin/env bash
set -euo pipefail

TASK_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="$TASK_ROOT/submission/Implementations/Reference_Implementation/Amoeba-576/src"
OUT="$TASK_ROOT/experiments/amoeba576-probe"

mkdir -p "$OUT"

gcc -std=c99 -O3 \
    -DSECURITY_LEVEL=128 \
    -I"$SRC/symmetric" \
    -I"$SRC/backend" \
    -I"$SRC/api" \
    "$TASK_ROOT/experiments/amoeba576_padding_probe.c" \
    "$SRC/symmetric/auxfunc.c" \
    "$SRC/symmetric/drng.c" \
    "$SRC/backend/randombytes.c" \
    "$SRC/backend/hamming.c" \
    "$SRC/backend/ntt_2s3t.c" \
    "$SRC/backend/zetas.c" \
    "$SRC/backend/poly.c" \
    "$SRC/backend/cpapke.c" \
    "$SRC/backend/ccakem.c" \
    "$SRC/api/KEM_AlgorithmInstance.c" \
    -o "$TASK_ROOT/experiments/amoeba576_padding_probe"

"$TASK_ROOT/experiments/amoeba576_padding_probe" "$OUT"
