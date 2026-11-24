#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "$0")" && pwd)"
bra="$root/source/Implementations/Optimized_Implementation/BRA-128"
mkdir -p "$root/logs"

make -C "$bra" clean
make -C "$bra" BRA-128-kat
(
  cd "$root"
  "$bra/bin/BRA-128-kat" \
    >"$root/logs/kat_plain.stdout.log" 2>"$root/logs/kat_plain.stderr.log"
)
cp "$root/output/KAT_KEM_BRA-128.txt" "$root/kats/KAT_KEM_BRA-128.plain.txt"
