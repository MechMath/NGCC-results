#!/usr/bin/env bash
set -u

root="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$root/logs"

run_case() {
  local name="$1"
  local log="$root/logs/${name}.stdout.log"
  local err="$root/logs/${name}.stderr.log"
  set +e
  timeout 15s "$root/oob_api_harness_plain" "$name" >"$log" 2>"$err"
  local rc=$?
  set -e
  printf '%s exit_code=%d\n' "$name" "$rc"
}

run_case positive
run_case positive-ignored-length
run_case enc_short_pk_guard
run_case dec_short_sk_guard
run_case dec_short_ct_guard
