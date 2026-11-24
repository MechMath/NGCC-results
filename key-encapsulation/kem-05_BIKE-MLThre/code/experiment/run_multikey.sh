#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
src="$root/original/extracted/Implementations/reference"
out="$root/experiment"
reps="${1:-5}"

gcc -m64 -O3 -std=c99 -I"$src" -DNIST_RAND=1 \
  -DBIKE_SECURITY_128 -DBIKE_MLTHRE_ENABLED=1 \
  "$out/multikey_bench.c" "$src/libbike_v2.a" -lcrypto -lm \
  -o "$out/multikey_bench"

env -i PATH="$PATH" LANG=C TZ=UTC \
  "$out/multikey_bench" "$reps" "$out/multikey_rows.csv" \
  > "$out/multikey_meta.json" 2> "$out/multikey_bench.log"

{
  date -u +'run_utc=%Y-%m-%dT%H:%M:%SZ'
  uname -a
  gcc --version | head -1
  lscpu | sed -n '1,20p'
  sha256sum "$out/multikey_bench.c" "$out/multikey_bench" \
    "$out/multikey_rows.csv" "$out/multikey_meta.json" \
    "$out/multikey_bench.log" "$root/original/BIKE_MLThre.zip" \
    "$src/libbike_v2.a"
} > "$out/multikey_environment_and_hashes.txt"
