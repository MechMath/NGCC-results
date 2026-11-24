#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$root"

out="experiments/reachability/results"
mkdir -p "$out"

printf 'compiler=' >"$out/environment.txt"
cc --version | sed -n '1p' >>"$out/environment.txt"
printf 'uname=' >>"$out/environment.txt"
uname -a >>"$out/environment.txt"
printf 'archive_sha256=' >>"$out/environment.txt"
sha256sum OPS-Digital-Signature-Algorithm.zip | cut -d' ' -f1 >>"$out/environment.txt"

for bits in 128 256 512; do
  ref="original-package/Implementations and Test_Vectors/Implementations/Reference_Implementation/OPSsig-${bits}"
  avx="original-package/Implementations and Test_Vectors/Implementations/Optimized_Implementation/OPSsig-${bits}-avx2"

  cc -O2 -std=c99 -Wall -Wextra -I"$ref" \
    -o "experiments/reachability/reference-${bits}" \
    experiments/reachability/valid_message_alloc_failure.c \
    "$ref"/SIG_AlgorithmInstance.c "$ref"/sign.c "$ref"/mult.c \
    "$ref"/packing.c "$ref"/polyvec.c "$ref"/poly.c "$ref"/ntt.c \
    "$ref"/reduce.c "$ref"/rounding.c "$ref"/auxfunc.c "$ref"/drng.c \
    2>"$out/reference-${bits}-build.log"

  cc -O3 -march=x86-64 -mavx2 -mtune=native -flto -fomit-frame-pointer \
    -std=c99 -Wpedantic -Wall -Wextra -I"$avx" \
    -o "experiments/reachability/avx2-${bits}" \
    experiments/reachability/valid_message_alloc_failure.c \
    "$avx"/SIG_AlgorithmInstance.c "$avx"/sign.c "$avx"/packing.c \
    "$avx"/polyvec.c "$avx"/poly.c "$avx"/rejsample.c "$avx"/ntt.c \
    "$avx"/pointwise.S "$avx"/consts.c "$avx"/reduce.c \
    "$avx"/rounding.c "$avx"/sm3x4.c "$avx"/auxfunc.c "$avx"/drng.c \
    2>"$out/avx2-${bits}-build.log"

  for variant in reference avx2; do
    bash -c "ulimit -v 98304; exec ./experiments/reachability/${variant}-${bits} 16777216" \
      >"$out/${variant}-${bits}-control-16MiB.txt"
    bash -c "ulimit -v 98304; exec ./experiments/reachability/${variant}-${bits} 67108864" \
      >"$out/${variant}-${bits}-pressure-64MiB.txt"
  done
done

sha256sum "$out"/*.txt "$out"/*.log >"$out/SHA256SUMS"
