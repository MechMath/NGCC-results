#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BASE="$ROOT/extracted/Implementations/Optimized_Implementation/bag_piglet128"
OUT="$ROOT/artifacts/harness128"
mkdir -p "$OUT"

gcc -std=gnu11 -O2 -g -Wall -Wextra -pedantic \
  -Wno-unused-parameter -Wno-unused-but-set-variable -Wno-sign-compare \
  -DBAG_PIGLET_KAT=1 \
  -I"$BASE/src/common" -I"$BASE/src/scheme" -I"$BASE/src/ffi" \
  -I"$BASE/src/rbc" -I"$BASE/src/kat" -I"$BASE/lib/api_pkc" \
  -I"$BASE/lib/randombytes" \
  "$ROOT/scripts/harness.c" \
  "$BASE"/src/common/*.c "$BASE"/src/scheme/*.c "$BASE"/src/ffi/*.c \
  "$BASE"/src/rbc/*.c "$BASE"/src/kat/KEM_AlgorithmInstance.c \
  "$BASE"/lib/api_pkc/*.c "$BASE"/lib/randombytes/*.c \
  -pthread -o "$OUT/bag_piglet128-harness"

"$OUT/bag_piglet128-harness" >"$OUT/output.txt"
sha256sum "$ROOT/original/BAG-Piglet.zip" "$ROOT/original/kem-04-spec.pdf" \
  "$OUT/bag_piglet128-harness" "$OUT/output.txt"
