#!/usr/bin/env bash
set -euo pipefail

src_root=/home/mmat/mmat-preview/runs/ngcc-kem-06-ds01/slots/orch-graph/orch/originals/BRA/Implementations
script_dir=$(cd "$(dirname "$0")" && pwd)
out_root="$script_dir"
probe_src="$script_dir/cross_parameter_probe.c"

mkdir -p "$out_root/source"

patterns=(
  canonical zero ff
  lcg:1 lcg:2 lcg:3 lcg:4 lcg:5 lcg:6 lcg:7 lcg:8
  u_zero_v_ff u_ff_v_zero low_u low_v last_byte u_last_v_last
)

for variant in Reference_Implementation Optimized_Implementation; do
  for p in 128 256 512; do
    name="${variant}-BRA-${p}"
    dst="$out_root/source/$name"
    rm -rf "$dst"
    cp -a "$src_root/$variant/BRA-$p" "$dst"
    make -C "$dst" "BRA-$p" -j2 >"$out_root/$name.build.log" 2>&1
    gcc -std=c99 -O2 \
      -I"$dst" -I"$dst/src" -I"$dst/src/rbc-67" \
      -I"$dst/lib/random_source" -I"$dst/lib/wrapper" \
      -DKEM_HEADER="\"KEM_BRA-$p.h\"" \
      "$out_root/cross_parameter_probe.c" "$dst"/bin/build/*.o \
      -o "$dst/bin/cross_parameter_probe"
    : >"$out_root/$name.results.log"
    for pattern in "${patterns[@]}"; do
      printf '=== %s %s ===\n' "$name" "$pattern" >>"$out_root/$name.results.log"
      set +e
      "$dst/bin/cross_parameter_probe" "$pattern" \
        >>"$out_root/$name.results.log" 2>&1
      status=$?
      set -e
      printf 'process_exit=%d\n' "$status" >>"$out_root/$name.results.log"
    done
  done
done
