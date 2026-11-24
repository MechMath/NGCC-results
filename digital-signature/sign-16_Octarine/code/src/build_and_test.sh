#!/usr/bin/env bash
set -euo pipefail

task_root="$(cd "$(dirname "$0")/.." && pwd)"
orig_root="$task_root/src/original/Implementations"
work_root="$task_root/work"
art_root="$task_root/artifacts"
log_root="$task_root/logs"

mkdir -p "$work_root/trees" "$work_root/bin" "$art_root" "$log_root"

families=(Reference_Implementation Optimized_Implementation Additional_Implementation)
profiles=(128 256 512)

compile_tree() {
  local srcdir="$1"
  local out="$2"
  local family="$3"
  local profile="$4"
  local common=( -I"$srcdir" -I"$srcdir/utils" -I"$srcdir/arith" )
  local sources=(
    "$srcdir/arith/fprime.c"
    "$srcdir/arith/poly.c"
    "$srcdir/arith/ring.c"
    "$srcdir/arith/packing.c"
    "$srcdir/arith/uniform.c"
    "$srcdir/sign_ring.c"
    "$srcdir/sign.c"
    "$srcdir/crt.c"
  )
  local utils=()

  if [[ "$family" == "Reference_Implementation" ]]; then
    utils=( "$srcdir/utils/auxfunc.c" "$srcdir/utils/drng.c" )
  elif [[ "$family" == "Optimized_Implementation" ]]; then
    sources+=(
      "$srcdir/arith/ntt.S" "$srcdir/arith/intt.S" "$srcdir/arith/pointwise.S"
      "$srcdir/arith/poly_avx.S" "$srcdir/arith/packing_avx.S" "$srcdir/crt_avx.S"
    )
    utils=( "$srcdir/utils/auxfunc.c" "$srcdir/utils/drng.c" )
  else
    common+=( -I"$srcdir/utils/keccak4x" )
    sources+=(
      "$srcdir/arith/ntt.S" "$srcdir/arith/intt.S" "$srcdir/arith/pointwise.S"
      "$srcdir/arith/poly_avx.S" "$srcdir/arith/packing_avx.S" "$srcdir/crt_avx.S"
    )
    utils=(
      "$srcdir/utils/fips202.c" "$srcdir/utils/fips202x4.c"
      "$srcdir/utils/keccak4x/KeccakP-1600-times4-SIMD256.c"
      "$srcdir/utils/drng.c"
    )
  fi

  local cflags=( -O2 -std=c11 -DRRLWR_SECURITY_LEVEL="$profile" )
  if [[ "$family" != "Reference_Implementation" ]]; then
    cflags+=( -mavx2 -mbmi2 )
  fi

  gcc "${cflags[@]}" "${common[@]}" \
    "${sources[@]}" "${utils[@]}" "$task_root/src/harness.c" \
    -o "$out"
}

for family in "${families[@]}"; do
  for profile in "${profiles[@]}"; do
    id="${family%%_Implementation}-$profile"
    origin="$orig_root/$family/Octarine-$profile"
    orig_tree="$work_root/trees/$id-original"
    patch_tree="$work_root/trees/$id-ceil"
    rm -rf "$orig_tree" "$patch_tree"
    cp -a "$origin" "$orig_tree"
    cp -a "$origin" "$patch_tree"

    perl -0pi -e 's/RRLWR_SIGN_MAX_TAU_BYTES, ctilde, 0, 0/\(RRLWR_SIGN_TAU + 7\) \/ 8, ctilde, 0, 0/g' \
      "$patch_tree/sign_ring.c"

    grep -q '(RRLWR_SIGN_TAU + 7) / 8, ctilde, 0, 0' "$patch_tree/sign_ring.c"

    compile_tree "$orig_tree" "$work_root/bin/$id-original" "$family" "$profile" \
      2> "$log_root/$id-original.build.stderr"
    compile_tree "$patch_tree" "$work_root/bin/$id-ceil" "$family" "$profile" \
      2> "$log_root/$id-ceil.build.stderr"

    mkdir -p "$art_root/$id-original" "$art_root/$id-ceil"
    "$work_root/bin/$id-original" generate "$art_root/$id-original" \
      > "$log_root/$id-original.generate.stdout" 2> "$log_root/$id-original.generate.stderr"
    "$work_root/bin/$id-ceil" generate "$art_root/$id-ceil" \
      > "$log_root/$id-ceil.generate.stdout" 2> "$log_root/$id-ceil.generate.stderr"

    set +e
    "$work_root/bin/$id-original" verify "$art_root/$id-original/pk.bin" "$art_root/$id-original/sig.bin" \
      > "$log_root/$id-original.selfverify.stdout" 2> "$log_root/$id-original.selfverify.stderr"
    echo "$?" > "$log_root/$id-original.selfverify.exit"
    "$work_root/bin/$id-ceil" verify "$art_root/$id-ceil/pk.bin" "$art_root/$id-ceil/sig.bin" \
      > "$log_root/$id-ceil.selfverify.stdout" 2> "$log_root/$id-ceil.selfverify.stderr"
    echo "$?" > "$log_root/$id-ceil.selfverify.exit"
    "$work_root/bin/$id-original" verify "$art_root/$id-ceil/pk.bin" "$art_root/$id-ceil/sig.bin" \
      > "$log_root/$id-original.verify-patch.stdout" 2> "$log_root/$id-original.verify-patch.stderr"
    echo "$?" > "$log_root/$id-original.verify-patch.exit"
    "$work_root/bin/$id-ceil" verify "$art_root/$id-original/pk.bin" "$art_root/$id-original/sig.bin" \
      > "$log_root/$id-ceil.verify-original.stdout" 2> "$log_root/$id-ceil.verify-original.stderr"
    echo "$?" > "$log_root/$id-ceil.verify-original.exit"
    set -e
  done
done
