#!/bin/bash
set -eu

ROOT_DIR=${ROOT_DIR:-"$(cd "$(dirname "$0")/.." && pwd)"}
CC=${CC:-gcc}

SECURITY_LIST=${SECURITY_LIST:-"128 256 512"}

for security in $SECURITY_LIST; do
  case "$security" in
    128) ref_def=-DBIKE_SECURITY_128 ;;
    256) ref_def=-DBIKE_SECURITY_256 ;;
    512) ref_def=-DBIKE_SECURITY_512 ;;
  esac

  ref_inc="$ROOT_DIR/work/reference"
  ref_lib="$ROOT_DIR/artifacts/reference-libs/$security/libbike_v2.a"
  ref_out="$ROOT_DIR/artifacts/harness-output/reference-$security"
  ref_bin="$ROOT_DIR/artifacts/harness-bin/reference-$security"
  mkdir -p "$ref_out" "$ROOT_DIR/artifacts/harness-bin"
  "$CC" -O2 -std=c99 -DNIST_RAND=1 -DHARNESS_LABEL='"reference"' \
    -DHARNESS_SECURITY_BITS="$security" "$ref_def" \
    -I"$ref_inc" -I"$ref_inc/kat" -I"$ref_inc/FromNIST" \
    "$ROOT_DIR/harness/kem_harness.c" \
    "$ref_inc/kat/KEM_AlgorithmInstance.c" "$ref_inc/kat/drng.c" \
    "$ref_inc/FromNIST/rng.c" "$ref_lib" -lcrypto -lm -o "$ref_bin"
  "$ref_bin" "$ref_out" > "$ref_out/result.tsv" 2> "$ref_out/stderr.txt"

  opt_inc="$ROOT_DIR/work/optimized/bike_kem_ml"
  opt_lib="$ROOT_DIR/artifacts/optimized-build-$security/libbike.a"
  opt_out="$ROOT_DIR/artifacts/harness-output/optimized-$security"
  opt_bin="$ROOT_DIR/artifacts/harness-bin/optimized-$security"
  mkdir -p "$opt_out"
  "$CC" -O2 -std=c99 -DHARNESS_LABEL='"optimized"' \
    -DHARNESS_SECURITY_BITS="$security" -DSECURITY_BITS="$security" \
    -I"$opt_inc/include" -I"$opt_inc/include/internal" \
    -I"$opt_inc/kat" -I"$opt_inc/tests/FromNIST" \
    "$ROOT_DIR/harness/kem_harness.c" \
    "$opt_inc/kat/KEM_AlgorithmInstance.c" "$opt_inc/kat/drng.c" \
    "$opt_inc/tests/FromNIST/rng.c" "$opt_lib" -lcrypto -lm -o "$opt_bin"
  "$opt_bin" "$opt_out" > "$opt_out/result.tsv" 2> "$opt_out/stderr.txt"
done
