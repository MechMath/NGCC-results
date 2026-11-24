#!/bin/bash
set -eu

ROOT_DIR=${ROOT_DIR:-"$(cd "$(dirname "$0")/.." && pwd)"}
CC=${CC:-gcc}
OUT_DIR=${OUT_DIR:-"$ROOT_DIR/artifacts/reference-decoder"}
mkdir -p "$OUT_DIR/bin" "$OUT_DIR/results"

for security in 128 256 512; do
  inc="$ROOT_DIR/work/reference"
  bin="$OUT_DIR/bin/reference-decoder-$security"
  "$CC" -O2 -std=c99 -DNIST_RAND=1 \
    -DHARNESS_SECURITY_BITS="$security" "-DBIKE_SECURITY_$security" \
    "-DBIKE_MLTHRE_ENABLED=1" -I"$inc" \
    "$ROOT_DIR/harness/reference_decoder_probe.c" \
    "$ROOT_DIR/artifacts/reference-libs/$security/libbike_v2.a" \
    -lcrypto -lm -o "$bin"
  "$bin" "$ROOT_DIR/artifacts/harness-output/reference-$security/sk.bin" \
    "$ROOT_DIR/artifacts/harness-output/reference-$security/ct.bin" \
    "$OUT_DIR/results/reference-decoder-$security.tsv"
done
