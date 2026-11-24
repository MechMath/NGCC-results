#!/usr/bin/env bash
set -euo pipefail

src=/home/mmat/mmat-preview/runs/ngcc-sign-13-ds01/insights/a8129b4d096f5dd1/authors/25f9d35be85a49da/native/original/submission/Implementations/Reference_Implementation/GreatWall128s
case_prefix=/home/mmat/mmat-preview/runs/ngcc-sign-13-ds01/insights/a8129b4d096f5dd1/authors/25f9d35be85a49da/native/evidence/generated/gw128s
here=$(cd "$(dirname "$0")" && pwd)

sources=(
  SIG_AlgorithmInstance.c drng.c api.c aes.c aes_impl.c block.c block_impl.c
  faest.c greatwall.c greatwall-128-matrix.c greatwall_impl.c hash.c
  KeccakHash.c KeccakP-1600-reference.c KeccakSponge.c owf_proof.c
  polynomials.c polynomials_impl.c prgs.c quicksilver.c
  randomness_randombytes.c small_vole.c transpose.c universal_hash.c util.c
  vector_com.c vole_check.c vole_commit.c
)

cd "$src"
gcc -O1 -g -std=c11 -march=x86-64 -w -fno-omit-frame-pointer \
  -fsanitize=address,undefined -I. \
  "$here/leak_harness.c" "${sources[@]}" -lcrypto -o "$here/leak_harness"

export ASAN_OPTIONS='detect_leaks=1:abort_on_error=0:halt_on_error=0:allocator_may_return_null=1'
export UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1'
set +e
"$here/leak_harness" honest "$case_prefix" >"$here/honest.stdout" 2>"$here/honest.stderr"
honest_rc=$?
"$here/leak_harness" forbidden-delta "$case_prefix" >"$here/forbidden.stdout" 2>"$here/forbidden.stderr"
forbidden_rc=$?
set -e
printf 'honest_rc=%d forbidden_rc=%d\n' "$honest_rc" "$forbidden_rc" | tee "$here/exit-status.txt"
grep -q 'ret=0' "$here/honest.stdout"
grep -q 'ret=-1' "$here/forbidden.stdout"
grep -q 'Direct leak of 720880 byte(s)' "$here/forbidden.stderr"
grep -q 'batch_vector_verify .*vector_com.c:767' "$here/forbidden.stderr"
test ! -s "$here/honest.stderr"
printf 'confirmed: rejected exact-length signature leaks the vector tree allocation\n'
