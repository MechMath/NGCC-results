#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "$0")" && pwd)"
base="$root/ops/Implementations and Test_Vectors/Implementations"

ref_sources=(
  sign.c SIG_AlgorithmInstance.c auxfunc.c drng.c mult.c ntt.c
  packing.c poly.c polyvec.c reduce.c rounding.c
)
avx2_sources=(
  sign.c SIG_AlgorithmInstance.c packing.c polyvec.c poly.c rejsample.c
  ntt.c pointwise.S consts.c reduce.c rounding.c sm3x4.c auxfunc.c drng.c
)
ref_profiles=(OPSsig-128 OPSsig-256 OPSsig-512)
avx2_profiles=(OPSsig-128-avx2 OPSsig-256-avx2 OPSsig-512-avx2)

test "$(sha256sum "$root/ops.zip" | cut -d' ' -f1)" = \
  02322c6792259231ab8eb3cc094be32be02a1b9b6b1d7c86b0029c37b0f04d09
test "$(sha256sum "$root/sign-17-spec.pdf" | cut -d' ' -f1)" = \
  1b5dc50ff728b2698bda90928251bae4e6cac4e138c82359f6f263cb6914078f
test "$(sha256sum "$root/ops/Algorithm specifications.pdf" | cut -d' ' -f1)" = \
  1b5dc50ff728b2698bda90928251bae4e6cac4e138c82359f6f263cb6914078f

for profile in "${ref_profiles[@]}"; do
  dir="$base/Reference_Implementation/$profile"
  make -C "$dir" clean >/dev/null
  make -C "$dir" -j1 test >"$root/repro-make-$profile.log" 2>&1
  (
    cd "$dir"
    cc -O2 -std=c99 -Wall -Wextra -I. "$root/malloc_fail_test.c" \
      "${ref_sources[@]}" -Wl,--wrap=malloc -o "$root/repro-$profile"
  )
  "$root/repro-$profile" >"$root/repro-$profile.out"
done

for profile in "${avx2_profiles[@]}"; do
  dir="$base/Optimized_Implementation/$profile"
  make -C "$dir" clean >/dev/null
  make -C "$dir" -j1 test >"$root/repro-make-$profile.log" 2>&1
  (
    cd "$dir"
    cc -O3 -march=x86-64 -mavx2 -mtune=native -flto \
      -fomit-frame-pointer -std=c99 -Wpedantic -Wall -Wextra -I. \
      "$root/malloc_fail_test.c" "${avx2_sources[@]}" \
      -Wl,--wrap=malloc -o "$root/repro-$profile"
  )
  "$root/repro-$profile" >"$root/repro-$profile.out"
done

for profile in "${ref_profiles[@]}" "${avx2_profiles[@]}"; do
  printf '%s\n' "--- $profile"
  cat "$root/repro-$profile.out"
done
