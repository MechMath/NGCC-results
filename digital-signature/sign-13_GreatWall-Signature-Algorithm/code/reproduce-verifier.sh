#!/usr/bin/env bash
set -euo pipefail

task_root="$(cd "$(dirname "$0")" && pwd)"
src="$task_root/original/submission/Implementations/Reference_Implementation/GreatWall128s"
generated="$task_root/evidence/generated/gw128s"
mkdir -p "$task_root/evidence/rebuild" "$task_root/evidence/replay"

common_sources=(
  SIG_AlgorithmInstance.c drng.c api.c aes.c aes_impl.c block.c block_impl.c
  faest.c greatwall.c greatwall-128-matrix.c greatwall_impl.c hash.c
  KeccakHash.c KeccakP-1600-reference.c KeccakSponge.c owf_proof.c
  polynomials.c polynomials_impl.c prgs.c quicksilver.c
  randomness_randombytes.c small_vole.c transpose.c universal_hash.c util.c
  vector_com.c vole_check.c vole_commit.c
)

cd "$src"
gcc -O1 -g -std=c11 -march=x86-64 -w \
  -fno-omit-frame-pointer -fno-sanitize-recover=all \
  -fsanitize=address,undefined -I. \
  "$task_root/harness/gw128s_verify_harness.c" "${common_sources[@]}" \
  -lcrypto -o "$task_root/harness/gw128s_verify_asan" \
  2> "$task_root/evidence/rebuild/build-asan.stderr.txt"

export ASAN_OPTIONS='abort_on_error=1:halt_on_error=1:detect_leaks=0:allocator_may_return_null=1'
export UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1'

"$task_root/harness/gw128s_verify_asan" verify ONE "$generated" 6 0 0 raw \
  > "$task_root/evidence/replay/honest.stdout.txt" \
  2> "$task_root/evidence/replay/honest.stderr.txt"

"$task_root/harness/gw128s_verify_asan" fuzz "$generated" 5 0 100000 20261114 10000 \
  > "$task_root/evidence/replay/random100k.stdout.txt" \
  2> "$task_root/evidence/replay/random100k.stderr.txt"

printf 'reproduction complete\n'
