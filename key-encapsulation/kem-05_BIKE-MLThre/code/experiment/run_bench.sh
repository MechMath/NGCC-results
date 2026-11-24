#!/usr/bin/env bash
set -euo pipefail

sec="${1:-128}"
reps="${2:-7}"
root="$(cd "$(dirname "$0")/.." && pwd)"
src="$root/original/extracted/Implementations/reference"
out="$root/experiment"

make -C "$src" clean
make -C "$src" SECURITY="$sec" -j2

gcc -m64 -O3 -std=c99 -I"$src" -DNIST_RAND=1 \
  -DBIKE_SECURITY_"$sec" -DBIKE_MLTHRE_ENABLED=1 \
  "$out/timing_bench.c" "$src/libbike_v2.a" -lcrypto -lm \
  -o "$out/timing_bench_$sec"

"$out/timing_bench_$sec" "$reps" "$out/timing_rows_${sec}.csv" \
  > "$out/timing_meta_${sec}.json" 2> "$out/timing_bench_${sec}.log"

sha256sum "$out/timing_bench.c" "$out/timing_bench_$sec" \
  "$out/timing_rows_${sec}.csv" "$out/timing_meta_${sec}.json" \
  "$out/timing_bench_${sec}.log" > "$out/timing_artifacts_${sec}.sha256"
