#!/usr/bin/env bash
set -u

root="$(cd "$(dirname "$0")/.." && pwd)"
base="$root/src/Implementation codes and test vectors/Shuttle 算法实现源代码及测试向量/Implementations/Reference_Implementation/SHUTTLE-128"
out="$root/experiments/reproduced"
mkdir -p "$out"

if [[ ! -d "$root/src" ]]; then
  python3 -m zipfile -e "$root/originals/shuttle.zip" "$root/src"
fi

scheme_sources=(
  "$base/SIG_AlgorithmInstance.c"
  "$base/sign.c"
  "$base/polyvec.c"
  "$base/sampler.c"
  "$base/sampler_u.c"
  "$base/irs.c"
  "$base/rounding.c"
  "$base/packing.c"
  "$base/poly.c"
  "$base/poly_ntt.c"
  "$base/reduce.c"
  "$base/rans.c"
  "$base/approx_exp.c"
  "$base/approx_log.c"
  "$base/symmetric.c"
  "$base/drng.c"
  "$base/auxfunc.c"
  "$base/ntt/q15361n256/ntt_ref.c"
)

common=(-std=c99 -O2 -g -Wall -Wextra -Wpedantic
        -I"$root" -I"$base" -I"$base/ntt/q15361n256" -DSHUTTLE_MODE=128)

gcc "${common[@]}" "$root/experiments/short_pk_harness.c" \
  "${scheme_sources[@]}" -o "$out/short_pk_release"

asan=(-std=c99 -O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined
      -Wall -Wextra -Wpedantic
      -I"$root" -I"$base" -I"$base/ntt/q15361n256" -DSHUTTLE_MODE=128)

gcc "${asan[@]}" "$root/experiments/short_pk_harness.c" \
  "${scheme_sources[@]}" -o "$out/short_pk_asan"

summary="$out/summary.txt"
: > "$summary"
for mode in valid altered_message altered_signature malformed_full_pk short_pk; do
  set +e
  ASAN_OPTIONS=abort_on_error=1:detect_leaks=0 UBSAN_OPTIONS=halt_on_error=0 \
    "$out/short_pk_asan" "$mode" >"$out/$mode.stdout" 2>"$out/$mode.stderr"
  rc=$?
  set -e
  printf 'asan %-20s exit=%s\n' "$mode" "$rc" >> "$summary"
done

set +e
"$out/short_pk_release" valid >"$out/release_valid.stdout" 2>"$out/release_valid.stderr"
rc=$?
printf 'release %-17s exit=%s\n' valid "$rc" >> "$summary"
"$out/short_pk_release" short_pk_guard >"$out/release_short_pk_guard.stdout" 2>"$out/release_short_pk_guard.stderr"
rc=$?
printf 'release %-17s exit=%s\n' short_pk_guard "$rc" >> "$summary"
set -e

sha256sum "$root/originals/shuttle.zip" \
  "$root/experiments/short_pk_harness.c" \
  "$out/short_pk_release" "$out/short_pk_asan" > "$out/hashes.txt"

cat "$summary"
