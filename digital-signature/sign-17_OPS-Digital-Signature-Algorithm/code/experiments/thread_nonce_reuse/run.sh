#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
REF="$ROOT/original-package/Implementations and Test_Vectors/Implementations/Reference_Implementation/OPSsig-128"
EXP="$ROOT/experiments/thread_nonce_reuse"
OUT="$EXP/results"
SCHED_OUT="$EXP/results-scheduled"

mkdir -p "$OUT" "$SCHED_OUT"

gcc -O2 -g -std=c11 -pthread -Wall -Wextra -Werror \
  -I"$REF" \
  -o "$EXP/concurrent_nonce_reuse" \
  "$EXP/concurrent_nonce_reuse.c" \
  "$REF/SIG_AlgorithmInstance.c" "$REF/sign.c" "$REF/mult.c" \
  "$REF/packing.c" "$REF/polyvec.c" "$REF/poly.c" "$REF/ntt.c" \
  "$REF/reduce.c" "$REF/rounding.c" "$REF/auxfunc.c" "$REF/drng.c" \
  -Wl,--wrap=get_random_number

"$EXP/concurrent_nonce_reuse" "$OUT" | tee "$OUT/run.txt"
set +e
python3 "$EXP/recover_secret.py" "$OUT" | tee "$OUT/recovery.txt"
unscheduled_status=${PIPESTATUS[0]}
set -e
echo "unscheduled_recovery_status=$unscheduled_status" | tee "$OUT/recovery.status"

OPS_SCHEDULE_SAME_STATE=1 "$EXP/concurrent_nonce_reuse" "$SCHED_OUT" \
  | tee "$SCHED_OUT/run.txt"
python3 "$EXP/recover_secret.py" "$SCHED_OUT" | tee "$SCHED_OUT/recovery.txt"

gcc -O2 -g -std=c11 -Wall -Wextra -Werror \
  -I"$REF" \
  -o "$EXP/forge_recovered_key" \
  "$EXP/forge_recovered_key.c" \
  "$REF/SIG_AlgorithmInstance.c" "$REF/sign.c" "$REF/mult.c" \
  "$REF/packing.c" "$REF/polyvec.c" "$REF/poly.c" "$REF/ntt.c" \
  "$REF/reduce.c" "$REF/rounding.c" "$REF/auxfunc.c" "$REF/drng.c"

"$EXP/forge_recovered_key" "$SCHED_OUT" | tee "$SCHED_OUT/forgery.txt"
sha256sum "$OUT"/*.bin > "$OUT/SHA256SUMS"
sha256sum "$SCHED_OUT"/*.bin > "$SCHED_OUT/SHA256SUMS"
