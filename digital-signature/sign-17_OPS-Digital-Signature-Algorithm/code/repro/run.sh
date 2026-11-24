#!/usr/bin/env bash
set -euo pipefail

orch="/home/mmat/mmat-preview/runs/ngcc-sign-17-ds01/slots/orch-graph/orch"
pkg="$orch/original-package/Implementations and Test_Vectors/Implementations"
here="$(cd "$(dirname "$0")" && pwd)"
out="$here/results"
mkdir -p "$out"

{
  printf 'compiler='; cc --version | sed -n '1p'
  printf 'uname='; uname -a
  printf 'archive_sha256='; sha256sum "$orch/OPS-Digital-Signature-Algorithm.zip" | cut -d' ' -f1
  printf 'harness_sha256='; sha256sum "$here/valid_message_alloc_failure.c" | cut -d' ' -f1
} >"$out/environment.txt"

for bits in 128 256 512; do
  ref="$pkg/Reference_Implementation/OPSsig-$bits"
  avx="$pkg/Optimized_Implementation/OPSsig-$bits-avx2"

  cc -O2 -std=c99 -Wall -Wextra -I"$ref" \
    -o "$here/reference-$bits" \
    "$here/valid_message_alloc_failure.c" \
    "$ref"/SIG_AlgorithmInstance.c "$ref"/sign.c "$ref"/mult.c \
    "$ref"/packing.c "$ref"/polyvec.c "$ref"/poly.c "$ref"/ntt.c \
    "$ref"/reduce.c "$ref"/rounding.c "$ref"/auxfunc.c "$ref"/drng.c \
    2>"$out/reference-$bits-build.log"

  cc -O3 -march=x86-64 -mavx2 -mtune=native -flto -fomit-frame-pointer \
    -std=c99 -Wpedantic -Wall -Wextra -I"$avx" \
    -o "$here/avx2-$bits" \
    "$here/valid_message_alloc_failure.c" \
    "$avx"/SIG_AlgorithmInstance.c "$avx"/sign.c "$avx"/packing.c \
    "$avx"/polyvec.c "$avx"/poly.c "$avx"/rejsample.c "$avx"/ntt.c \
    "$avx"/pointwise.S "$avx"/consts.c "$avx"/reduce.c \
    "$avx"/rounding.c "$avx"/sm3x4.c "$avx"/auxfunc.c "$avx"/drng.c \
    2>"$out/avx2-$bits-build.log"

  for variant in reference avx2; do
    bash -c "ulimit -v 98304; exec '$here/$variant-$bits' 16777216" \
      >"$out/$variant-$bits-control-16MiB.txt"
    bash -c "ulimit -v 98304; exec '$here/$variant-$bits' 67108864" \
      >"$out/$variant-$bits-pressure-64MiB.txt"
  done
done

sha256sum "$here"/reference-{128,256,512} "$here"/avx2-{128,256,512} \
  "$here/valid_message_alloc_failure.c" "$here/run.sh" \
  "$pkg"/Reference_Implementation/OPSsig-{128,256,512}/sign.c \
  "$pkg"/Optimized_Implementation/OPSsig-{128,256,512}-avx2/sign.c \
  "$out"/*.txt "$out"/*.log >"$out/SHA256SUMS"
