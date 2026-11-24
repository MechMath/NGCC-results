#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
src="$root/original/extracted-local/Implementations/reference"
out="$root/experiment/rotation_branch_coverage"

rm -rf "$out"
mkdir -p "$out/runs" "$out/gcov"

make -C "$src" clean >/dev/null
make -C "$src" SECURITY=128 CFLAGS='-m64 -O0 -g -std=c99 --coverage' >/dev/null

gcc -m64 -O0 -g -std=c99 --coverage -I"$src" -DNIST_RAND=1 \
  -DBIKE_SECURITY_128 -DBIKE_MLTHRE_ENABLED=1 \
  "$root/experiment/rotation_branch_bench.c" "$src/libbike_v2.a" \
  -lcrypto -lm -o "$out/rotation_branch_bench"

{
  date -u +'run_utc=%Y-%m-%dT%H:%M:%SZ'
  uname -a
  gcc --version | head -1
  printf 'mask_weight=8\nshifts=0..15\n'
  sha256sum "$root/experiment/rotation_branch_bench.c" \
    "$src/decode_ml.c" "$src/kem.c" "$src/Makefile"
} > "$out/environment_and_hashes.txt"

for shift in $(seq 0 15); do
  find "$src" -name '*.gcda' -delete
  env -i PATH="$PATH" LANG=C TZ=UTC \
    "$out/rotation_branch_bench" "$shift" 8 > "$out/runs/shift_${shift}.txt"
  cp "$src/.build/128/decode_ml.gcda" "$out/gcov/decode_ml_${shift}.gcda"
  (
    cd "$src"
    gcov -b -c -o .build/128 decode_ml.c >/dev/null
    cp decode_ml.c.gcov "$out/gcov/decode_ml_${shift}.gcov"
  )
done

make -C "$src" clean >/dev/null
