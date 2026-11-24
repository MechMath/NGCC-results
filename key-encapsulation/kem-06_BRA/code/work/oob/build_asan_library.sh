#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "$0")" && pwd)"
bra="$root/source/Implementations/Optimized_Implementation/BRA-128"
mkdir -p "$root/logs"

asan_flags='-O1 -g -march=x86-64 -mavx2 -mtune=native -fomit-frame-pointer -mpclmul -msse4.2 -maes -std=c99 -Wpedantic -Wall -Wextra -fsanitize=address -fno-omit-frame-pointer'
make -C "$bra" clean
make -C "$bra" BRA-128-kat CC=gcc C_FLAGS="$asan_flags"
(
  cd "$root"
  ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 \
    "$bra/bin/BRA-128-kat" \
    >"$root/logs/kat.stdout.log" 2>"$root/logs/kat.stderr.log"
)
cp "$root/output/KAT_KEM_BRA-128.txt" "$root/kats/KAT_KEM_BRA-128.asan.txt"
