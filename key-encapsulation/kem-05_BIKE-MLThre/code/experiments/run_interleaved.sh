#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$root/logs/interleaved"

for round in 1 2 3 4 5 6 7 8; do
  taskset -c 2 "$root/reference128/timing_i_ref_on" 2 4 8 \
    > "$root/logs/interleaved/ref_on_${round}.csv"
  taskset -c 2 "$root/reference128/timing_i_ref_off" 2 4 8 \
    > "$root/logs/interleaved/ref_off_${round}.csv"
  taskset -c 4 "$root/optimization128/timing_i_opt_on" 4 4 8 \
    > "$root/logs/interleaved/opt_on_${round}.csv"
  taskset -c 4 "$root/optimization128_off/timing_i_opt_off" 4 4 8 \
    > "$root/logs/interleaved/opt_off_${round}.csv"
done
