#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
exp="$root/experiments"

profiles=(576 864 1152 1728 2304)
levels=(128 192 256 384 512)
implementations=(Reference_Implementation Optimized_Implementation)

mkdir -p "$exp/build_logs"

for impl in "${implementations[@]}"; do
  prefix=ref
  if [[ "$impl" == "Optimized_Implementation" ]]; then
    prefix=opt
  fi
  for i in "${!profiles[@]}"; do
    profile=${profiles[$i]}
    level=${levels[$i]}
    src="$root/submission/Implementations/$impl/Amoeba-$profile/src"
    exe="$exp/padding_probe_${prefix}_${profile}"
    out="$exp/padding_probe_${prefix}_${profile}.out"
    log="$exp/build_logs/padding_probe_${prefix}_${profile}.log"
    gcc -O2 -fgnu89-inline -DSECURITY_LEVEL="$level" \
      -I"$src/backend" -I"$src/symmetric" \
      "$exp/padding_probe.c" "$src/backend/"*.c "$src/symmetric/"*.c \
      -o "$exe" 2>"$log"
    "$exe" | tee "$out"
  done
done
