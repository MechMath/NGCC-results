#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
srcroot="$root/source/archive/Implementations"
outroot="$root/build/probes"
exp="$root/experiments"

mkdir -p "$outroot" "$exp/results"

build_variant() {
    local name="$1"
    local dir="$2"
    local cflags="$3"
    local out="$outroot/$name"
    mkdir -p "$out"
    mapfile -t csrc < <(find "$dir" -maxdepth 1 -type f -name '*.c' ! -name 'KAT_SIG.c' -print | sort)
    mapfile -t asrc < <(find "$dir" -maxdepth 1 -type f -name '*.S' ! -name 'shuffle.S' -print | sort)
    gcc $cflags -I"$dir" "$exp/api_probe.c" "${csrc[@]}" "${asrc[@]}" -o "$out/api_probe"
}

build_variant bit128_ref "$srcroot/Reference_Implementation/BiT-128" "-std=c99 -O2 -Wpedantic -Wall -Wextra"
build_variant bit256_ref "$srcroot/Reference_Implementation/BiT-256" "-std=c99 -O2 -Wpedantic -Wall -Wextra"
build_variant bit512_ref "$srcroot/Reference_Implementation/BiT-512" "-std=c99 -O2 -Wpedantic -Wall -Wextra"
build_variant bit128_avx2 "$srcroot/Optimized_Implementation/BiT-128-avx2" "-std=c99 -O2 -march=x86-64 -mavx2 -DASM_ALIASES -Wpedantic -Wall -Wextra"
build_variant bit256_avx2 "$srcroot/Optimized_Implementation/BiT-256-avx2" "-std=c99 -O2 -march=x86-64 -mavx2 -DASM_ALIASES -Wpedantic -Wall -Wextra"
build_variant bit512_avx2 "$srcroot/Optimized_Implementation/BiT-512-avx2" "-std=c99 -O2 -march=x86-64 -mavx2 -DASM_ALIASES -Wpedantic -Wall -Wextra"

for p in 128 256 512; do
    "$outroot/bit${p}_ref/api_probe" gen "$exp/results/bit${p}_ref"
    "$outroot/bit${p}_avx2/api_probe" gen "$exp/results/bit${p}_avx2"
    for impl in ref avx2; do
        "$outroot/bit${p}_${impl}/api_probe" mutate \
          "$exp/results/bit${p}_ref.bin" "$exp/results/bit${p}_${impl}_from_ref.csv"
    done
done
