#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd "$(dirname "$0")" && pwd)
out_root="$script_dir"
probe_src="$out_root/cross_parameter_probe.c"
mkdir -p "$out_root/asan"

run_asan() {
  local variant=$1 p=$2 pattern=$3 tag=$4
  local src="$out_root/source/${variant}-BRA-${p}"
  local dst="$out_root/asan/${variant}-BRA-${p}"
  rm -rf "$dst"
  cp -a "$src" "$dst"
  make -C "$dst" clean >/dev/null 2>&1 || true
  make -C "$dst" "BRA-$p" -j2 \
    C_FLAGS='-O1 -g -fsanitize=address -fno-omit-frame-pointer -std=c99 -w' \
    >"$out_root/$tag.asan-build.log" 2>&1
  gcc -O1 -g -fsanitize=address -fno-omit-frame-pointer -std=c99 \
    -I"$dst" -I"$dst/src" -I"$dst/src/rbc-67" \
    -I"$dst/lib/random_source" -I"$dst/lib/wrapper" \
    -DKEM_HEADER="\"KEM_BRA-$p.h\"" \
    "$probe_src" "$dst"/bin/build/*.o \
    -o "$dst/bin/cross_parameter_probe_asan"
  set +e
  ASAN_OPTIONS=abort_on_error=1:detect_leaks=0 \
    "$dst/bin/cross_parameter_probe_asan" "$pattern" \
    >"$out_root/$tag.asan.stdout.log" \
    2>"$out_root/$tag.asan.stderr.log"
  local status=$?
  set -e
  printf '%s\n' "$status" >"$out_root/$tag.asan.exit"
}

run_asan Reference_Implementation 256 zero ref256_zero
run_asan Optimized_Implementation 256 lcg:1 opt256_lcg1
run_asan Optimized_Implementation 128 lcg:1 opt128_lcg1
