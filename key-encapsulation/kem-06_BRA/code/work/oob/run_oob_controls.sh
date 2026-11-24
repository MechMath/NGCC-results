#!/usr/bin/env bash
set -u

root="$(cd "$(dirname "$0")" && pwd)"
bra="$root/source/Implementations/Optimized_Implementation/BRA-128"
mkdir -p "$root/logs"

run_case() {
  local name="$1"
  local log="$root/logs/${name}.stdout.log"
  local err="$root/logs/${name}.stderr.log"
  set +e
  ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 \
  UBSAN_OPTIONS=halt_on_error=1 \
    "$root/oob_api_harness" "$name" >"$log" 2>"$err"
  local rc=$?
  set -e
  printf '%s exit_code=%d\n' "$name" "$rc"
}

run_case positive
run_case positive-ignored-length
run_case enc_short_pk
run_case dec_short_sk
run_case dec_short_ct
run_case enc_short_pk_stack
run_case dec_short_sk_stack
run_case dec_short_ct_stack
