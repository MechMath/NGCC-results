#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ORIGINAL="$ROOT/originals/submission/Implementations/Optimized_Implementation/CEDRUSC-160f"
OUT="$ROOT/experiments/rebuilt-optimized"
EXPECTED_ZIP_SHA256="a31de849cf0a0703a4e57decbdf4d97b100d00dc74756feaded2c04a7593e110"

actual_zip_sha256="$(sha256sum "$ROOT/originals/cedrus+c.zip" | awk '{print $1}')"
if [[ "$actual_zip_sha256" != "$EXPECTED_ZIP_SHA256" ]]; then
  echo "submission ZIP hash mismatch" >&2
  exit 1
fi

STAGE="$(mktemp -d "${TMPDIR:-/tmp}/cedrus-optimized-160f-build.XXXXXX")"
trap 'rm -rf "$STAGE"' EXIT
cp -a "$ORIGINAL/." "$STAGE/"

make -C "$STAGE" -j"${JOBS:-4}" >/dev/null
mkdir -p "$OUT"

OBJECTS=(
  "$STAGE/sign.o"
  "$STAGE/address.o"
  "$STAGE/auxfunc.o"
  "$STAGE/counters.o"
  "$STAGE/drng.o"
  "$STAGE/hash_sm3.o"
  "$STAGE/hash_sm3x8.o"
  "$STAGE/merkle.o"
  "$STAGE/fors.o"
  "$STAGE/randombytes.o"
  "$STAGE/SIG_AlgorithmInstance.o"
  "$STAGE/sm3x8.o"
  "$STAGE/thash_sm3_simple.o"
  "$STAGE/thash_sm3_simplex8.o"
  "$STAGE/utils.o"
  "$STAGE/utils_avx2.o"
  "$STAGE/utilsx1.o"
  "$STAGE/wots.o"
  "$STAGE/wotsx1.o"
)

for experiment in forced_tree_oracle forced_tree_forge verify_forced_tree; do
  gcc -O3 -flto \
    -I"$STAGE" \
    -DPARAMS=cedrusc-sm3-160f \
    "$ROOT/experiments/${experiment}.c" \
    "${OBJECTS[@]}" \
    -o "$OUT/${experiment}_optimized_160f"
done

echo "built optimized experiments into $OUT from ZIP $EXPECTED_ZIP_SHA256"
