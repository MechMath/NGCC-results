#!/usr/bin/env bash
set -euo pipefail
src=refsrc-144d/Implementations/Reference_Implementation
common=(cbd.c fips202.c poly.c reduce.c precomp.c ntt.c polyvec.c owcpa.c
  kem.c verify.c hashkdf.c gen_a.c pack.c randombytes.c)
for p in 1 2 3; do
  case "$p" in
    1) name=I ;;
    2) name=II ;;
    3) name=III ;;
  esac
  dir="$src/Aigis-Enc+-$name"
  args=()
  for f in "${common[@]}"; do args+=("$dir/$f"); done
  gcc -std=c99 -O2 -g -Wall -Wextra -DPARAMS="$p" -DUSE_SHA3 \
    -I"$dir" ref_harness.c "${args[@]}" -o "ref_harness_o2_p$p" \
    2>"ordinary_p${p}_build.stderr"
  "./ref_harness_o2_p$p" >"ordinary_p${p}.json"
done
sha256sum ref_harness_o2_p* ordinary_p*.json > ordinary_hashes.txt
