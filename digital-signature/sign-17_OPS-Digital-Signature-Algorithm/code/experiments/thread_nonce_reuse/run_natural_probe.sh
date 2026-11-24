#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
REF="$ROOT/original-package/Implementations and Test_Vectors/Implementations/Reference_Implementation/OPSsig-128"
EXP="$ROOT/experiments/thread_nonce_reuse"
OUT="$EXP/results-natural"

mkdir -p "$OUT"

gcc -O2 -g -std=c11 -pthread -Wall -Wextra -Werror \
  -I"$REF" -o "$EXP/natural_race_probe" \
  "$EXP/natural_race_probe.c" "$REF/drng.c" \
  -Wl,--wrap=get_random_number

set +e
for threads in 8 16 32 64 128; do
  "$EXP/natural_race_probe" "$threads" | tee "$OUT/threads-$threads.txt"
done
set -e
