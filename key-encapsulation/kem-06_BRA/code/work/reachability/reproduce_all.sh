#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "$0")" && pwd)"
cd "$root"

./build_exact_ct_probe.sh >build_exact_ct_probe.log 2>&1
set +e
ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 \
  ./exact_ct_probe random1 >random1_asan.stdout.log 2>random1_asan.stderr.log
asan_status=$?
set -e
if [ "$asan_status" -ne 134 ]; then
  echo "expected ASan abort status 134, got $asan_status" >&2
  exit 1
fi
if ! grep -q 'heap-buffer-overflow' random1_asan.stderr.log; then
  echo "ASan heap-buffer-overflow was not reported" >&2
  exit 1
fi

./build_plain_exact_ct_probe.sh >build_plain_exact_ct_probe.log 2>&1
set +e
./exact_ct_probe_plain >exact_ct_probe_plain.stdout.log 2>exact_ct_probe_plain.stderr.log
plain_status=$?
set -e
if [ "$plain_status" -ne 139 ]; then
  echo "expected optimized SIGSEGV status 139, got $plain_status" >&2
  exit 1
fi
if ! grep -q 'case=canonical rc=0 equal=1' exact_ct_probe_plain.stdout.log; then
  echo "canonical positive control did not pass" >&2
  exit 1
fi

printf 'ASan exit=%d; optimized SIGSEGV exit=%d; canonical control passed\n' \
  "$asan_status" "$plain_status"
