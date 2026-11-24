#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

for spec in \
  "160s 0" \
  "160f 0" \
  "256s 0" \
  "256f 0" \
  "384s 0" \
  "384f 1" \
  "512s 0" \
  "512f 0"
do
  set -- $spec
  parameter="$1"
  vector="$2"

  for implementation in reference optimized; do
    binary="experiments/$implementation-$parameter/noncanonical_padding"
    kat="submission/Test_Vectors/KAT_SIG_Flextree-$parameter.txt"
    "$binary" "$kat" "$vector" "FlexTree-$parameter-$implementation"
    printf '\n'
  done
done
