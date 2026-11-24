#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$root/kats" "$root/logs"

{
  date -u
  uname -a
  gcc --version
  ldd --version | head -1
} >"$root/logs/environment.txt" 2>&1

"$root/build_asan_library.sh" >"$root/logs/build_asan.log" 2>&1
"$root/build_harness.sh" >>"$root/logs/build_asan.log" 2>&1
"$root/run_oob_controls.sh" | tee "$root/logs/asan_exit_summary.txt"

"$root/build_plain_library.sh" >"$root/logs/build_plain.log" 2>&1
"$root/build_plain_harness.sh" >>"$root/logs/build_plain.log" 2>&1
"$root/run_guard_controls.sh" | tee "$root/logs/guard_exit_summary.txt"
