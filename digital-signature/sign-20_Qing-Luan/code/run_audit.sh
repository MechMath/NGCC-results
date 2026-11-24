#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
SRC="$ROOT/extracted/Implementations and Test_Vectors/Implementations/Reference_Implementation/QingLuan-128"

test "$(sha256sum "$ROOT/QingLuan.zip" | cut -d' ' -f1)" = \
  2eb8f3ed205eb7c7e8b3108a997b59643d1aa5579035b8093b4ddbe051a48007

gcc -O2 -g -std=c11 -DQINGLUAN_128 \
  -I"$SRC/include" -I"$SRC/api_pkc" \
  -o "$ROOT/harness_api" "$ROOT/harness_api.c" \
  "$SRC/api_pkc/SIG_AlgorithmInstance.c" \
  "$SRC/src/fq_arith.c" "$SRC/src/hash.c" "$SRC/src/utils.c" \
  "$SRC/src/restr.c" "$SRC/src/rsdp.c" "$SRC/src/mpc.c" \
  "$SRC/src/keygen.c" "$SRC/src/sign.c" "$SRC/src/verify.c"
"$ROOT/harness_api" | tee "$ROOT/harness_api.normal.out"

gcc -O2 -std=c11 -I"$SRC/include" \
  -o "$ROOT/harness_mutations" "$ROOT/harness_mutations.c" \
  "$SRC/src/fq_arith.c" "$SRC/src/hash.c" "$SRC/src/utils.c" \
  "$SRC/src/restr.c" "$SRC/src/rsdp.c" "$SRC/src/mpc.c" \
  "$SRC/src/keygen.c" "$SRC/src/sign.c" "$SRC/src/verify.c"
"$ROOT/harness_mutations" | tee "$ROOT/harness_mutations.out"

gcc -O2 -std=c11 -I"$SRC/include" -I"$SRC/api_pkc" \
  -o "$ROOT/harness_hashdiff" "$ROOT/harness_hashdiff.c" \
  "$SRC/src/hash.c" "$SRC/src/utils.c" "$SRC/api_pkc/auxfunc.c"
"$ROOT/harness_hashdiff" | tee "$ROOT/harness_hashdiff.out"

gcc -O1 -g -std=c11 -DQINGLUAN_128 -fsanitize=address \
  -fno-omit-frame-pointer -I"$SRC/include" -I"$SRC/api_pkc" \
  -o "$ROOT/harness_shortkey_asan_only" "$ROOT/harness_shortkey.c" \
  "$SRC/api_pkc/SIG_AlgorithmInstance.c" "$SRC/api_pkc/utils_adapter.c" \
  "$SRC/api_pkc/hash_adapter.c" "$SRC/api_pkc/drng.c" \
  "$SRC/api_pkc/auxfunc.c" "$SRC/src/fq_arith.c" "$SRC/src/restr.c" \
  "$SRC/src/rsdp.c" "$SRC/src/mpc.c" "$SRC/src/keygen.c" \
  "$SRC/src/sign.c" "$SRC/src/verify.c"

set +e
ASAN_OPTIONS=detect_leaks=0:abort_on_error=0 \
  "$ROOT/harness_shortkey_asan_only" pk \
  >"$ROOT/shortkey_pk_asan_only.out" 2>"$ROOT/shortkey_pk_asan_only.err"
pk_rc=$?
ASAN_OPTIONS=detect_leaks=0:abort_on_error=0 \
  "$ROOT/harness_shortkey_asan_only" sk \
  >"$ROOT/shortkey_sk_asan_only.out" 2>"$ROOT/shortkey_sk_asan_only.err"
sk_rc=$?
set -e
test "$pk_rc" -ne 0
test "$sk_rc" -ne 0
grep -q "heap-buffer-overflow" "$ROOT/shortkey_pk_asan_only.err"
grep -q "heap-buffer-overflow" "$ROOT/shortkey_sk_asan_only.err"
echo "ASan short-key reproductions passed: pk_rc=$pk_rc sk_rc=$sk_rc"
