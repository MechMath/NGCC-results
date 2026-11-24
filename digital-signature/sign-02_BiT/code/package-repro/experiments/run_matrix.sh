#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
ref="$root/submission/Implementations/Reference_Implementation/BiT-512"
avx2="$root/submission/Implementations/Optimized_Implementation/BiT-512-avx2"
out="$root/experiments/oom-matrix"
harness="$root/experiments/oom_audit_matrix.c"
wrapper="$root/experiments/malloc_audit_wrap.c"
cc=${CC:-gcc}

mkdir -p "$out"

for opt in O0 O2; do
  ref_bin="$out/reference-$opt"
  avx2_bin="$out/avx2-$opt"
  ref_log="$out/reference-$opt.txt"
  avx2_log="$out/avx2-$opt.txt"
  ref_no_prior="$out/reference-$opt-no-prior.txt"
  avx2_no_prior="$out/avx2-$opt-no-prior.txt"

  "$cc" "-$opt" -std=c99 -I "$ref" \
    "$harness" "$wrapper" \
    $(find "$ref" -maxdepth 1 -name '*.c' ! -name 'KAT_SIG.c' -print) \
    -Wl,--wrap=malloc \
    -o "$ref_bin"

  "$cc" "-$opt" -std=c99 -DASM_ALIASES -march=x86-64 -mavx2 -I "$avx2" \
    "$harness" "$wrapper" \
    $(find "$avx2" -maxdepth 1 -name '*.c' ! -name 'KAT_SIG.c' -print) \
    $(find "$avx2" -maxdepth 1 -name '*.S' -print) \
    -Wl,--wrap=malloc \
    -o "$avx2_bin"

  "$ref_bin" "$ref_log"
  "$avx2_bin" "$avx2_log"
  "$ref_bin" "$ref_no_prior" no-prior
  "$avx2_bin" "$avx2_no_prior" no-prior
done

sha256sum "$out"/*.txt
