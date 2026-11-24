#!/bin/sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
REF="$ROOT/extracted/BiT/Implementations/Reference_Implementation/BiT-128"
AVX="$ROOT/extracted/BiT/Implementations/Optimized_Implementation/BiT-128-avx2"
OUT="$ROOT/experiments/bin"
SRC="$ROOT/experiments/bit128_driver.c"

mkdir -p "$OUT"

REF_C=$(find "$REF" -maxdepth 1 -type f -name '*.c' ! -name 'KAT_SIG.c' | sort)
AVX_C=$(find "$AVX" -maxdepth 1 -type f -name '*.c' ! -name 'KAT_SIG.c' | sort)
AVX_S=$(find "$AVX" -maxdepth 1 -type f -name '*.S' | sort)

# shellcheck disable=SC2086
gcc -std=c99 -O2 -Wall -Wextra -I"$REF" -DDRIVER_LABEL='"reference"' \
  "$SRC" $REF_C -o "$OUT/bit128_reference"

# shellcheck disable=SC2086
gcc -std=c99 -O3 -march=x86-64 -mavx2 -mtune=native -flto -fomit-frame-pointer \
  -Wall -Wextra -DASM_ALIASES -I"$AVX" -DDRIVER_LABEL='"avx2"' \
  "$SRC" $AVX_C $AVX_S -o "$OUT/bit128_avx2"

printf 'built: %s\n' "$OUT/bit128_reference"
printf 'built: %s\n' "$OUT/bit128_avx2"
sha256sum "$OUT/bit128_reference" "$OUT/bit128_avx2"
