#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
REF="$ROOT/original-package/Implementations and Test_Vectors/Implementations/Reference_Implementation/OPSsig-128"
EXP="$ROOT/experiments/thread_nonce_reuse"
OUT="$EXP/results-natural-sign"

mkdir -p "$OUT"

gcc -O2 -g -std=c11 -pthread -Wall -Wextra -Werror \
  -I"$REF" \
  -o "$EXP/concurrent_nonce_natural" \
  "$EXP/concurrent_nonce_natural.c" \
  "$REF/SIG_AlgorithmInstance.c" "$REF/sign.c" "$REF/mult.c" \
  "$REF/packing.c" "$REF/polyvec.c" "$REF/poly.c" "$REF/ntt.c" \
  "$REF/reduce.c" "$REF/rounding.c" "$REF/auxfunc.c" "$REF/drng.c" \
  -Wl,--wrap=get_random_number

"$EXP/concurrent_nonce_natural" "$OUT" 16 | tee "$OUT/run.txt"
python3 "$EXP/recover_secret.py" "$OUT" | tee "$OUT/recovery.txt"
"$EXP/forge_recovered_key" "$OUT" | tee "$OUT/forgery.txt"
sha256sum "$OUT"/*.bin > "$OUT/SHA256SUMS"
