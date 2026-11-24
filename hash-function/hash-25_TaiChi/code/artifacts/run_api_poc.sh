#!/usr/bin/env bash
set -euo pipefail

commit=dc66c6cb3c06e75bdea0048e21fa4e13c63f00af
root="$(cd "$(dirname "$0")/.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

for d in 512 768 1024; do
    case "$d" in
        512) dir=TaiChi-512 ;;
        768) dir=TaiChi-768 ;;
        1024) dir=TaiChi-1024 ;;
    esac
    url="https://raw.githubusercontent.com/ngcc-dev/ngcc-harness/$commit/hash-25/TaiChi/Implementations/Reference_Implementation/$dir"
    mkdir -p "$tmp/$d"
    curl -L --fail --silent --show-error \
        "$url/CryptHash_AlgorithmInstance.c" \
        -o "$tmp/$d/CryptHash_AlgorithmInstance.c"
    curl -L --fail --silent --show-error \
        "$url/CryptHash_AlgorithmInstance.h" \
        -o "$tmp/$d/CryptHash_AlgorithmInstance.h"
    gcc -std=c99 -O2 -I"$tmp/$d" \
        "$root/artifacts/verify_malloc_api.c" \
        "$tmp/$d/CryptHash_AlgorithmInstance.c" \
        -Wl,--wrap=malloc \
        -o "$tmp/$d/verify"
    printf 'TaiChi-%s: ' "$d"
    "$tmp/$d/verify"
done
