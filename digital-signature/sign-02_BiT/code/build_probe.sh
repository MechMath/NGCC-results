#!/usr/bin/env bash
set -euo pipefail

build_reference() {
    local dir="$1"
    local out="$2"
    local sources
    sources=$(find "$dir" -maxdepth 1 -name '*.c' ! -name 'KAT_SIG.c' -printf '%p ')
    # shellcheck disable=SC2086
    gcc -std=c99 -O2 -pthread -I"$dir" -I. concurrency_probe.c $sources -o "$out"
}

build_avx2() {
    local dir="$1"
    local out="$2"
    local c_sources
    local asm_sources
    c_sources=$(find "$dir" -maxdepth 1 -name '*.c' ! -name 'KAT_SIG.c' -printf '%p ')
    asm_sources="$dir/f1600x4.S $dir/ntt.S $dir/intt.S $dir/pointwise.S"
    # shellcheck disable=SC2086
    gcc -std=c99 -O3 -march=x86-64 -mavx2 -mtune=native -flto \
        -fomit-frame-pointer -pthread -DASM_ALIASES -I"$dir" -I. \
        concurrency_probe.c $c_sources $asm_sources -o "$out"
}

build_reference bit-src/Implementations/Reference_Implementation/BiT-128 \
    concurrency_probe_ref128
build_avx2 bit-src/Implementations/Optimized_Implementation/BiT-128-avx2 \
    concurrency_probe_avx128
build_reference bit-src/Implementations/Reference_Implementation/BiT-256 \
    concurrency_probe_ref256
build_avx2 bit-src/Implementations/Optimized_Implementation/BiT-256-avx2 \
    concurrency_probe_avx256
