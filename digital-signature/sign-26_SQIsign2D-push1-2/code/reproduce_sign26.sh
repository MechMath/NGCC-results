#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
CHECKOUT="$ROOT/artifacts/checkout"
SIGN26="$CHECKOUT/sign-26"
GMP_HEADER="$ROOT/artifacts/deps/root/usr/include/x86_64-linux-gnu"
GMP_LIB="$ROOT/artifacts/deps/lib"
OUT="$ROOT/artifacts/runs"
LOG="$ROOT/artifacts/runs/level1-kat.stdout.log"

test "$(git -C "$CHECKOUT" rev-parse HEAD)" = \
  "dc66c6cb3c06e75bdea0048e21fa4e13c63f00af"
test "$(sha256sum "$SIGN26/sign-26-spec.pdf" | cut -d' ' -f1)" = \
  "1363945ff198e9ca48e7a7dbe39d488c590580d746c56b7f10e30d51f86059f6"
test "$(sha256sum "$SIGN26/Implementations/sqisign2d_lvl1/src/sqisigndim2/ref/sqisigndim2x/sign.c" | cut -d' ' -f1)" = \
  "6a2634f7845b2f22ed22f6d94f5370d45fa81c8525f96acbf82c5af3b7a87b59"

mkdir -p "$OUT" "$GMP_LIB"
ln -sfn /usr/lib/x86_64-linux-gnu/libgmp.so.10 "$GMP_LIB/libgmp.so"

env CPATH="$GMP_HEADER" LIBRARY_PATH="$GMP_LIB" \
  make -C "$CHECKOUT/api" -j8 harness
env CPATH="$GMP_HEADER" LIBRARY_PATH="$GMP_LIB" \
  make -C "$SIGN26" -j8 lib/libSQIsign2D-lvl1.so

set -o pipefail
timeout 180s "$CHECKOUT/bin/ngcc_kat" \
  --out-dir "$OUT" \
  --kat-sha "$SIGN26/kat.sha256" \
  --label SQIsign2D-lvl1 \
  --count 10 \
  --timeout 150 \
  --quiet \
  "$SIGN26/lib/libSQIsign2D-lvl1.so" | tee "$LOG"

tail -n 1 "$LOG" | grep -F "RESULT sign-26 SQIsign2D-lvl1 PASS"
