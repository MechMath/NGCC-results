#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
impl="$root/DARTS_extracted/Implementations/Reference_Implementation/DARTS128"
out="$root/experiments"
srcs=(
  sign.c packing.c polyvec.c poly.c ntt.c reduce.c sampler.c encoding.c
  polyfix.c polymat.c fft.c fixpoint.c symmetric.c drng.c auxfunc.c
  SIG_AlgorithmInstance.c
)

if [ ! -d "$impl" ]; then
  python3 - "$root/DARTS.zip" "$root/DARTS_extracted" <<'PY'
import sys
from zipfile import ZipFile
with ZipFile(sys.argv[1]) as archive:
    archive.extractall(sys.argv[2])
PY
fi

paths=()
for source in "${srcs[@]}"; do
  paths+=("$impl/$source")
done

cc -O2 -std=gnu99 -fcommon -I "$impl" \
  -o "$out/honest_witness" "$out/honest_witness.c" "${paths[@]}" -lm
cc -O2 -std=gnu99 -fcommon -I "$impl" \
  -o "$out/verify_wrapper" "$out/wrapper_rng_attack.c" "${paths[@]}" -lm
cc -O2 -std=gnu99 -fcommon -I "$impl" \
  -o "$out/compare_unpack" "$out/compare_unpack.c" \
  "$impl/packing.c" "$impl/polyvec.c" "$impl/poly.c" "$impl/ntt.c" \
  "$impl/reduce.c" "$impl/sampler.c" "$impl/encoding.c" \
  "$impl/polyfix.c" "$impl/polymat.c" "$impl/fft.c" \
  "$impl/fixpoint.c" "$impl/symmetric.c" "$impl/auxfunc.c" -lm

"$out/honest_witness" "malleability-witness" "$out/honest.pk" "$out/honest.sig"
python3 "$out/mutate_lowbits.py" 128 "$out/honest.sig" "$out/honest.mutated.sig" \
  > "$out/honest.mutation.txt"
python3 "$out/flip_bit.py" "$out/honest.sig" "$out/honest.corrupt.sig" 1000 \
  > "$out/honest.corrupt.txt"

"$out/verify_wrapper" verify "$out/honest.pk" "$out/honest.sig" \
  "malleability-witness" > "$out/honest.original.verify.txt"
"$out/verify_wrapper" verify "$out/honest.pk" "$out/honest.mutated.sig" \
  "malleability-witness" > "$out/honest.mutated.verify.txt"
if "$out/verify_wrapper" verify "$out/honest.pk" "$out/honest.corrupt.sig" \
    "malleability-witness" > "$out/honest.corrupt.verify.txt"; then
  echo "unexpected corruption acceptance" >&2
  exit 1
fi
"$out/compare_unpack" "$out/honest.sig" "$out/honest.mutated.sig" \
  > "$out/honest.compare.txt"

cat "$out/honest.mutation.txt"
cat "$out/honest.compare.txt"
cat "$out/honest.original.verify.txt"
cat "$out/honest.mutated.verify.txt"
cat "$out/honest.corrupt.verify.txt"
sha256sum "$out/honest.pk" "$out/honest.sig" "$out/honest.mutated.sig"
