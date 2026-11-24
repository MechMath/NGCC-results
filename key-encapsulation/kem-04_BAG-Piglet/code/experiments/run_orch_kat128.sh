#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
src="$root/materials/original/Implementations/Reference_Implementation/bag_piglet128"
out="$root/artifacts/orch-kat128"
mkdir -p "$out"

gcc -std=c11 -O2 -DBAG_PIGLET_KAT=1 \
  -I"$src/src/common" \
  -I"$src/src/scheme" \
  -I"$src/src/ffi" \
  -I"$src/src/rbc" \
  -I"$src/src/kat" \
  -I"$src/lib/api_pkc" \
  -I"$src/lib/randombytes" \
  "$src"/src/common/*.c \
  "$src"/src/scheme/*.c \
  "$src"/src/ffi/*.c \
  "$src"/src/rbc/*.c \
  "$src"/lib/api_pkc/*.c \
  "$src"/lib/randombytes/*.c \
  "$src"/src/kat/KAT_KEM.c \
  "$src"/src/kat/KEM_AlgorithmInstance.c \
  -lpthread \
  -o "$out/bag_piglet128-kat"

(
  cd "$out"
  ./bag_piglet128-kat >kat.stdout 2>kat.stderr
  sha256sum output/KAT_KEM_bag_piglet_128.txt
  cmp output/KAT_KEM_bag_piglet_128.txt \
    "$root/materials/original/Test_Vectors/KAT_KEM_bag_piglet_128.txt"
)

printf 'KAT reproduction matched the shipped BAG-Piglet-128 vector.\n'
