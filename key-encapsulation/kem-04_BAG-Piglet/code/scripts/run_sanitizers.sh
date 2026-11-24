#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BASE="$ROOT/extracted/Implementations/Optimized_Implementation/bag_piglet128"
OUT="$ROOT/artifacts/sanitize128"
mkdir -p "$OUT"

sources=(
  "$ROOT/scripts/harness.c"
  "$BASE"/src/common/*.c
  "$BASE"/src/scheme/*.c
  "$BASE"/src/ffi/*.c
  "$BASE"/src/rbc/*.c
  "$BASE"/src/kat/KEM_AlgorithmInstance.c
  "$BASE"/lib/api_pkc/*.c
  "$BASE"/lib/randombytes/*.c
)
includes=(
  -I"$BASE/src/common" -I"$BASE/src/scheme" -I"$BASE/src/ffi"
  -I"$BASE/src/rbc" -I"$BASE/src/kat" -I"$BASE/lib/api_pkc"
  -I"$BASE/lib/randombytes"
)
common=(
  -std=gnu11 -O1 -g -fno-omit-frame-pointer -Wall -Wextra -pedantic
  -Wno-unused-parameter -Wno-unused-but-set-variable -Wno-sign-compare
  -DBAG_PIGLET_KAT=1 "${includes[@]}"
)

gcc "${common[@]}" -fsanitize=undefined -fno-sanitize-recover=undefined \
  "${sources[@]}" -pthread -o "$OUT/harness-ubsan"
set +e
"$OUT/harness-ubsan" >"$OUT/ubsan.stdout" 2>"$OUT/ubsan.stderr"
ubsan_rc=$?
set -e

gcc "${common[@]}" -fsanitize=address \
  "${sources[@]}" -pthread -o "$OUT/harness-asan"
set +e
ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 \
  "$OUT/harness-asan" short-ct >"$OUT/short-ct.stdout" 2>"$OUT/short-ct.stderr"
asan_rc=$?
set -e

printf 'ubsan_rc=%d asan_short_ct_rc=%d\n' "$ubsan_rc" "$asan_rc"
printf '%s\n' 'UBSAN:'
sed -n '1,40p' "$OUT/ubsan.stderr"
printf '%s\n' 'ASAN:'
sed -n '1,35p' "$OUT/short-ct.stderr"
