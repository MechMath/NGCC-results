#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
SUB="$ROOT/original/submission"
OUT="$ROOT/experiments/poc"

mkdir -p "$OUT"

for bits in 128 256 384 512; do
  inst="$SUB/Implementations/Reference_Implementation/Loong-Block-ms-$bits"
  m=$(sed -n 's/^#define LOONG_M //p' "$inst/src/loong_parameters.h" | tr -d ' ')
  rbc="lib/rbc-$m"

  python3 "$OUT/extract_kat.py" \
    "$SUB/Test_Vectors/KAT_KEM_BAG-Loong-$bits.txt" \
    "$OUT/kat_$bits" >/dev/null

  (
    cd "$inst"
    gcc -std=c99 -O2 -w -Isrc -Ilib/api_pkc -I"$rbc" \
      "$OUT/recover_x.c" \
      "$rbc/rbc_elt.c" "$rbc/rbc_vec.c" \
      src/augabidulin.c src/ct_util.c src/gabidulin.c \
      src/loong_api_random.c src/loong_hash.c src/loong_kem.c \
      src/loong_pke.c src/loong_support.c src/loong_xof_reader.c \
      src/parsing.c src/qpoly.c lib/api_pkc/auxfunc.c \
      lib/api_pkc/drng.c -o "$OUT/recover_x_$bits"
  )

  "$OUT/recover_x_$bits" kat \
    "$OUT/kat_$bits/pk.bin" "$OUT/kat_$bits/sk.bin" \
    "$OUT/kat_$bits/ct.bin" "$OUT/kat_$bits/ss.bin" |
    tee "$OUT/kat_attack_$bits.out"
done
