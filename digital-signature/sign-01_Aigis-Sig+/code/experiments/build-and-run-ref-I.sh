#!/usr/bin/env bash
set -euo pipefail

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
src="$root/extracted/Implementations/Implementations/Reference_Implementation/Aigis-Sig+-I"
out="$root/experiments"

/usr/bin/cc -Wall -Wextra -march=native -mtune=native \
  -fomit-frame-pointer -O3 -Wno-incompatible-pointer-types \
  -DPARAMS=1 -DUSE_SHA3 \
  "$src/append_extension_test.c" \
  "$src/sign.c" "$src/polyvec.c" "$src/packing.c" "$src/poly.c" \
  "$src/reduce.c" "$src/ntt.c" "$src/rounding.c" "$src/fips202.c" \
  "$src/hashkdf.c" "$src/auxfunc.c" "$src/SIG_AlgorithmInstance.c" \
  "$src/drng.c" "$src/pspm.c" \
  -o "$out/ref-I-append-extension"

(
  cd "$root"
  "$out/ref-I-append-extension" \
    | tee "$out/ref-I-append-extension.deterministic.out"
)
