#!/bin/bash
set -eu

ROOT_DIR=${ROOT_DIR:-"$(cd "$(dirname "$0")/.." && pwd)"}
CC=${CC:-gcc}
OUT_ROOT=${OUT_ROOT:-"$ROOT_DIR/artifacts/decoder-mutations"}
MODE_128=${MODE_128:-full}
MODE_256=${MODE_256:-full}
OPT_MODE_512=${OPT_MODE_512:-full}
REF_MODE_512=${REF_MODE_512:-full}

mkdir -p "$OUT_ROOT/bin"

build_ref() {
  security=$1
  def="-DBIKE_SECURITY_$security"
  inc="$ROOT_DIR/work/reference"
  out="$OUT_ROOT/bin/reference-$security"
  "$CC" -O2 -std=c99 -DNIST_RAND=1 -DHARNESS_LABEL='"reference"' \
    -DHARNESS_SECURITY_BITS="$security" "$def" \
    -I"$inc" -I"$inc/kat" -I"$inc/FromNIST" \
    "$ROOT_DIR/harness/decoder_mutation_harness.c" \
    "$inc/kat/KEM_AlgorithmInstance.c" "$inc/kat/drng.c" \
    "$inc/FromNIST/rng.c" \
    "$ROOT_DIR/artifacts/reference-libs/$security/libbike_v2.a" \
    -lcrypto -lm -o "$out"
}

build_opt() {
  security=$1
  inc="$ROOT_DIR/work/optimized/bike_kem_ml"
  out="$OUT_ROOT/bin/optimized-$security"
  "$CC" -O2 -std=c99 -DHARNESS_LABEL='"optimized"' \
    -DHARNESS_SECURITY_BITS="$security" -DSECURITY_BITS="$security" \
    -I"$inc/include" -I"$inc/include/internal" \
    -I"$inc/kat" -I"$inc/tests/FromNIST" \
    "$ROOT_DIR/harness/decoder_mutation_harness.c" \
    "$inc/kat/KEM_AlgorithmInstance.c" "$inc/kat/drng.c" \
    "$inc/tests/FromNIST/rng.c" \
    "$ROOT_DIR/artifacts/optimized-build-$security/libbike.a" \
    -lcrypto -lm -o "$out"
}

run_one() {
  impl=$1
  security=$2
  mode=$3
  in="$ROOT_DIR/artifacts/harness-output/$impl-$security"
  out="$OUT_ROOT/$impl-$security"
  mkdir -p "$out"
  "$OUT_ROOT/bin/$impl-$security" "$in/sk.bin" "$in/ct.bin" "$in/ss.bin" \
    "$out" "$mode" > "$out/stdout.txt" 2> "$out/stderr.txt"
}

for security in 128 256 512; do
  [ -e "$ROOT_DIR/artifacts/reference-libs/$security/libbike_v2.a" ] || continue
  build_ref "$security"
  build_opt "$security"
done

run_one reference 128 "$MODE_128"
run_one optimized 128 "$MODE_128"
run_one reference 256 "$MODE_256"
run_one optimized 256 "$MODE_256"
run_one reference 512 "$REF_MODE_512"
run_one optimized 512 "$OPT_MODE_512"
