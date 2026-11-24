#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
cd "$ROOT"

test "$(sha256sum artifacts/source/BiT.zip | awk '{print $1}')" = \
  "698fbe834279a4100a66c20f3e0b634c738e1150936acf74b55efc6db6975e8d"

REF=artifacts/source/extracted/Implementations/Reference_Implementation/BiT-512
AVX=artifacts/source/extracted/Implementations/Optimized_Implementation/BiT-512-avx2

make -C "$REF" clean all
make -C "$AVX" clean all

ref_objs=$(find "$REF" -maxdepth 1 -name '*.o' ! -name 'packing.o' -print | sort)
avx_objs=$(find "$AVX" -maxdepth 1 -name '*.o' ! -name 'packing.o' -print | sort)

gcc -std=c99 -Wpedantic -Wall -Wextra -O2 -I"$REF" \
  artifacts/harness/natural_pressure.c $ref_objs "$REF/packing.o" \
  -o artifacts/build/natural_pressure_reference

gcc -O3 -march=x86-64 -mavx2 -mtune=native -fomit-frame-pointer \
  -std=c99 -Wpedantic -Wall -Wextra -DASM_ALIASES -I"$AVX" \
  artifacts/harness/natural_pressure.c $avx_objs "$AVX/packing.o" \
  -o artifacts/build/natural_pressure_avx2 -lm

prlimit --as=67108864 -- ./artifacts/build/natural_pressure_reference \
  artifacts/logs/repro_ref_coarse 5064 1024 1048576 \
  >artifacts/logs/repro_ref_coarse.stdout \
  2>artifacts/logs/repro_ref_coarse.stderr

prlimit --as=67108864 -- ./artifacts/build/natural_pressure_reference \
  artifacts/logs/repro_ref_fine 5064 1024 4096 \
  >artifacts/logs/repro_ref_fine.stdout \
  2>artifacts/logs/repro_ref_fine.stderr

prlimit --as=67108864 -- ./artifacts/build/natural_pressure_avx2 \
  artifacts/logs/repro_avx_coarse 5064 1024 1048576 \
  >artifacts/logs/repro_avx_coarse.stdout \
  2>artifacts/logs/repro_avx_coarse.stderr

prlimit --as=67108864 -- ./artifacts/build/natural_pressure_avx2 \
  artifacts/logs/repro_avx_fine 5064 1024 4096 \
  >artifacts/logs/repro_avx_fine.stdout \
  2>artifacts/logs/repro_avx_fine.stderr

grep -E 'target_probe|sign2_rc|sign2_vs_' artifacts/logs/repro_*_*.stdout
