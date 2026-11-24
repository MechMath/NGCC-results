#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
outdir="$root/api-bin"
mkdir -p "$outdir"

for n in 128 256 384 512; do
    d="$root/Reference_Implementation/Loong-Block-ms-$n"
    rbc=$(basename "$(find "$d/lib" -maxdepth 1 -type d -name 'rbc-*' | head -n 1)")
    cc -std=c99 -O2 -Wall -Wextra -Wpedantic \
        -I"$d/src" -I"$d/lib/api_pkc" -I"$d/lib/$rbc" \
        "$root/api_tests.c" \
        "$d/lib/$rbc/rbc_elt.c" "$d/lib/$rbc/rbc_vec.c" \
        "$d/src/KEM_AlgorithmInstance.c" "$d/src/augabidulin.c" \
        "$d/src/ct_util.c" "$d/src/gabidulin.c" \
        "$d/src/loong_api_random.c" "$d/src/loong_hash.c" \
        "$d/src/loong_kem.c" "$d/src/loong_pke.c" \
        "$d/src/loong_support.c" "$d/src/loong_xof_reader.c" \
        "$d/src/parsing.c" "$d/src/qpoly.c" \
        "$d/lib/api_pkc/auxfunc.c" "$d/lib/api_pkc/drng.c" \
        -o "$outdir/api-tests-$n"
done
