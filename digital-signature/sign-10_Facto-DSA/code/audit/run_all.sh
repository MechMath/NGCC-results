#!/bin/sh
set -eu

cd "$(dirname "$0")/.."
mkdir -p audit/bin audit/logs

(
  cd audit/source/Reference
  make clean all
) > audit/logs/build_reference_reproduce.log 2>&1
(
  cd audit/source/Optimized
  make clean all
) > audit/logs/build_optimized_reproduce.log 2>&1
(
  cd audit/source/Resource
  make clean all
) > audit/logs/build_resource_reproduce.log 2>&1

gcc -std=c99 -O2 -Wall -Wextra -Wpedantic \
  -I audit/source/Reference \
  audit/public_audit.c \
  audit/source/Reference/SIG_AlgorithmInstance.c \
  audit/source/Reference/auxfunc.c \
  audit/source/Reference/drng.c \
  -o audit/bin/audit_reference > audit/logs/build_audit_reference_reproduce.log 2>&1

gcc -std=c99 -O3 -flto -fomit-frame-pointer -Wpedantic -Wall -Wextra \
  -DFACTO_SIMD_AVX2=1 -march=x86-64 -mavx2 -mtune=native \
  -I audit/source/Optimized \
  audit/public_audit.c \
  audit/source/Optimized/SIG_AlgorithmInstance.c \
  audit/source/Optimized/auxfunc.c \
  audit/source/Optimized/drng.c \
  -o audit/bin/audit_optimized > audit/logs/build_audit_optimized_reproduce.log 2>&1

gcc -std=c99 -Os -flto -fomit-frame-pointer -Wpedantic -Wall -Wextra \
  -DFACTO_SIMD_AVX2=1 -march=x86-64 -mavx2 \
  -I audit/source/Resource \
  audit/public_audit.c \
  audit/source/Resource/SIG_AlgorithmInstance.c \
  audit/source/Resource/auxfunc.c \
  audit/source/Resource/drng.c \
  -o audit/bin/audit_resource > audit/logs/build_audit_resource_reproduce.log 2>&1

gcc -std=c99 -O1 -g -fno-omit-frame-pointer -fsanitize=address \
  -Wall -Wextra -Wpedantic \
  -I audit/source/Reference \
  audit/public_audit.c \
  audit/source/Reference/SIG_AlgorithmInstance.c \
  audit/source/Reference/auxfunc.c \
  audit/source/Reference/drng.c \
  -o audit/bin/audit_reference_asan > audit/logs/build_reference_asan_reproduce.log 2>&1

gcc -std=c99 -O1 -g -fno-omit-frame-pointer -fsanitize=undefined \
  -Wall -Wextra -Wpedantic \
  -I audit/source/Reference \
  audit/public_audit.c \
  audit/source/Reference/SIG_AlgorithmInstance.c \
  audit/source/Reference/auxfunc.c \
  audit/source/Reference/drng.c \
  -o audit/bin/audit_reference_ubsan > audit/logs/build_reference_ubsan_reproduce.log 2>&1

gcc -std=c99 -O2 -Wall -Wextra -Wpedantic -DAUDIT_INSTRUMENTED \
  -I audit/instrumented \
  audit/public_audit.c \
  audit/instrumented/SIG_AlgorithmInstance.c \
  audit/instrumented/auxfunc.c \
  audit/instrumented/drng.c \
  -o audit/bin/audit_ref_instrumented > audit/logs/build_instrumented_reproduce.log 2>&1

audit/bin/audit_reference controls > audit/logs/controls_reference_reproduce.txt
audit/bin/audit_optimized controls > audit/logs/controls_optimized_reproduce.txt
audit/bin/audit_resource controls > audit/logs/controls_resource_reproduce.txt
ASAN_OPTIONS=detect_leaks=0:halt_on_error=1 \
  audit/bin/audit_reference_asan controls > audit/logs/asan_reproduce.txt
UBSAN_OPTIONS=print_stacktrace=0:halt_on_error=0 \
  audit/bin/audit_reference_ubsan controls > audit/logs/ubsan_reproduce.txt 2>&1

audit/bin/audit_ref_instrumented population 1000 8 0 \
  > audit/logs/population_ref_1000x8_reproduce.csv
python3 audit/analyze_population.py \
  audit/logs/population_ref_1000x8_reproduce.csv \
  > audit/results_population_ref_1000x8_reproduce.json
