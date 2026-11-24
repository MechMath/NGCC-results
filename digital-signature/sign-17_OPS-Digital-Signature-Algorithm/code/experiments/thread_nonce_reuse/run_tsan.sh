#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
REF="$ROOT/original-package/Implementations and Test_Vectors/Implementations/Reference_Implementation/OPSsig-128"
EXP="$ROOT/experiments/thread_nonce_reuse"
OUT="$EXP/results"

mkdir -p "$OUT"

gcc -O1 -g -std=c11 -pthread -fsanitize=thread \
  -I"$REF" \
  -o "$EXP/concurrent_nonce_reuse_tsan" \
  "$EXP/concurrent_nonce_reuse.c" \
  "$REF/SIG_AlgorithmInstance.c" "$REF/sign.c" "$REF/mult.c" \
  "$REF/packing.c" "$REF/polyvec.c" "$REF/poly.c" "$REF/ntt.c" \
  "$REF/reduce.c" "$REF/rounding.c" "$REF/auxfunc.c" "$REF/drng.c" \
  -Wl,--wrap=get_random_number

set +e
"$EXP/concurrent_nonce_reuse_tsan" "$OUT" >"$OUT/tsan.stdout" 2>"$OUT/tsan.stderr"
status=$?
set -e
printf 'exit_status=%d\n' "$status" | tee "$OUT/tsan.status"
