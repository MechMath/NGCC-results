#!/usr/bin/env bash
set -u
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
  gcc -std=c99 -O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined \
    -Wall -Wextra -DPARAMS="$p" -DUSE_SHA3 -I"$dir" mdkem_harness.c \
    "${args[@]}" -o "mdkem_asan_p$p" 2>"mdkem_asan_p${p}_build.stderr"
  ASAN_OPTIONS=halt_on_error=1:abort_on_error=0:detect_leaks=0 \
    "./mdkem_asan_p$p" >"mdkem_asan_p${p}.stdout" 2>"mdkem_asan_p${p}.stderr"
  printf '%s' "$?" >"mdkem_asan_p${p}.exit"
done
