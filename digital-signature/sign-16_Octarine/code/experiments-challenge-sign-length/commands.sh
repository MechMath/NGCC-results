#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

COMMON="-O3 -Wall -Wextra -Wpedantic -Wmissing-prototypes -Wredundant-decls -Wshadow -Wpointer-arith -fomit-frame-pointer"
SRC="arith/fprime.c arith/poly.c arith/ring.c arith/packing.c arith/uniform.c sign_ring.c sign.c crt.c utils/auxfunc.c utils/drng.c"

build_one()
{
  src_dir=$1
  out=$2
  level=$3
  (
    cd "$src_dir"
    gcc -DRRLWR_SECURITY_LEVEL="$level" $COMMON \
      -I. -Iutils -Iarith \
      $SRC "$ROOT/cross_check.c" -o "$out"
  )
}

cd "$ROOT"

for level in 128 256 512
do
  orig="$ROOT/../../original/Implementations/Reference_Implementation/Octarine-$level"
  variant="$ROOT/Octarine-$level-specvariant"
  original_bin="$ROOT/original-$level-cross-check"
  variant_bin="$ROOT/specvariant-$level-cross-check"

  build_one "$orig" "$original_bin" "$level"
  build_one "$variant" "$variant_bin" "$level"

  "$original_bin" generate "original-$level"
  "$original_bin" verify "original-$level"
  "$variant_bin" generate "specvariant-$level"
  "$variant_bin" verify "specvariant-$level"

  if cmp -s "original-$level.sig" "specvariant-$level.sig"; then
    echo "level=$level signatures_match=yes"
  else
    echo "level=$level signatures_match=no"
  fi

  if "$variant_bin" verify "original-$level"; then
    echo "level=$level specvariant_accepts_original=yes"
  else
    echo "level=$level specvariant_accepts_original=no"
  fi

  if "$original_bin" verify "specvariant-$level"; then
    echo "level=$level original_accepts_specvariant=yes"
  else
    echo "level=$level original_accepts_specvariant=no"
  fi
done
