#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
for profile in 128 256 384 512; do
  base="$ROOT/extracted/Implementations/Optimized_Implementation/bag_piglet$profile"
  out="$ROOT/artifacts/kat$profile"
  mkdir -p "$out/run/output"
  gcc -std=gnu11 -O3 -Wall -Wextra -pedantic \
    -Wno-unused-parameter -Wno-unused-but-set-variable -Wno-sign-compare \
    -DBAG_PIGLET_KAT=1 \
    -I"$base/src/common" -I"$base/src/scheme" -I"$base/src/ffi" \
    -I"$base/src/rbc" -I"$base/src/kat" -I"$base/lib/api_pkc" \
    -I"$base/lib/randombytes" \
    "$base"/src/common/*.c "$base"/src/scheme/*.c "$base"/src/ffi/*.c \
    "$base"/src/rbc/*.c "$base"/src/kat/KAT_KEM.c \
    "$base"/src/kat/KEM_AlgorithmInstance.c "$base"/lib/api_pkc/*.c \
    "$base"/lib/randombytes/*.c -pthread -o "$out/kat"

  (cd "$out/run" && ../kat >kat.stdout 2>kat.stderr)
  generated="$out/run/output/KAT_KEM_bag_piglet_$profile.txt"
  expected="$ROOT/extracted/Test_Vectors/KAT_KEM_bag_piglet_$profile.txt"
  cmp "$generated" "$expected"
  printf 'profile=%s KAT_MATCH generated_sha256=' "$profile"
  sha256sum "$generated" | cut -d' ' -f1
done
