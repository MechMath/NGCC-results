#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
EM_SRC="$ROOT/artifacts/submission/unpacked/Implementations/Reference_Implementation/sm4th_em_d2_128f_loose"
NONEM_SRC="$ROOT/artifacts/submission/unpacked/Implementations/Reference_Implementation/sm4th_d3_128f_loose"
OUT="$ROOT/artifacts/experiments"

COMMON_CFLAGS=(-O2 -std=c11 -Wall -Wextra -include fallbacks.h
  -DSM4_SBOX_TABLE -DNDEBUG)

EM_SOURCES=(
  auxfunc.c bavc.c compat.c drng.c fields.c owf.c params.c prg.c
  random_oracle.c sig_impl.c sm4_witness.c sm4th_em_d2_128f_loose.c
  sm4th_sm4_128.c universal_hashing.c utils.c utils_sm4/sm4_affine.c
  utils_sm4/sm4_core.c utils_sm4/sm4_ecb.c utils_sm4/sm4_sbox.c vole.c
)

NONEM_SOURCES=(
  auxfunc.c bavc.c compat.c drng.c fields.c owf.c params.c prg.c
  random_oracle.c sig_impl.c sig_timing.c sm4_witness.c
  sm4th_d3_128f_loose.c sm4th_sm4_128.c universal_hashing.c utils.c
  utils_sm4/sm4_affine.c utils_sm4/sm4_core.c utils_sm4/sm4_ecb.c
  utils_sm4/sm4_sbox.c vole.c
)

build_em() {
  local main="$1" binary="$2"
  local abs_sources=()
  for f in "${EM_SOURCES[@]}"; do abs_sources+=("$EM_SRC/$f"); done
  gcc "${COMMON_CFLAGS[@]}" -I"$EM_SRC" -I"$EM_SRC/utils_sm4" \
    "$main" "${abs_sources[@]}" -lm -o "$binary"
}

build_nonem() {
  local main="$1" binary="$2"
  local abs_sources=()
  for f in "${NONEM_SOURCES[@]}"; do abs_sources+=("$NONEM_SRC/$f"); done
  gcc "${COMMON_CFLAGS[@]}" -I"$NONEM_SRC" -I"$NONEM_SRC/utils_sm4" \
    "$main" "${abs_sources[@]}" -lm -o "$binary"
}

build_em "$OUT/em_valid_key_control.c" "$OUT/em_valid_key_control"
build_em "$OUT/public_only_em_forgery.c" "$OUT/public_only_em_forgery"
build_nonem "$OUT/public_only_nonem_forgery.c" "$OUT/public_only_nonem_forgery"

"$OUT/em_valid_key_control"
"$OUT/public_only_em_forgery"
"$OUT/public_only_nonem_forgery"
