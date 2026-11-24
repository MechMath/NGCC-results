#!/usr/bin/env bash
set -euo pipefail

taskroot=/home/mmat/mmat-preview/runs/ngcc-sign-09-ds01
src=${DOVE_SRC:-"$taskroot/run/slots/b977949983924d87/refsrc/Digital_Signature-DOVE-x86-reference_implementation/API_PKC/Implementations/Reference_Implementation/DOVE_pkc_skc_ref"}
here=$(cd "$(dirname "$0")" && pwd)
out="$here/evidence"
mkdir -p "$out"

common=(
  -std=gnu11
  -DDOVE_PARAM_SET=DOVE128
  -I"$src"
  -I"$src/uov"
  "$here/dove_length_guard_test.c"
  "$src/SIG_AlgorithmInstance.c"
  "$src/auxfunc.c"
  "$src/drng.c"
  "$src/gf256.c"
  "$src/matrix.c"
  "$src/uov/blas_matrix_ref.c"
  -lm
)

cc -O1 -g -fsanitize=address -fno-omit-frame-pointer "${common[@]}" \
  -o "$out/dove_oob_asan"
cc -O2 "${common[@]}" -o "$out/dove_oob_plain"

set +e
ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 "$out/dove_oob_asan" sign_exact \
  >"$out/asan_sign_exact.stdout" 2>"$out/asan_sign_exact.stderr"
printf '%s\n' "$?" >"$out/asan_sign_exact.exit"

ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 "$out/dove_oob_asan" verify_truncated \
  >"$out/asan_verify_truncated.stdout" 2>"$out/asan_verify_truncated.stderr"
printf '%s\n' "$?" >"$out/asan_verify_truncated.exit"

"$out/dove_oob_plain" sign_guard \
  >"$out/plain_sign_guard.stdout" 2>"$out/plain_sign_guard.stderr"
printf '%s\n' "$?" >"$out/plain_sign_guard.exit"
set -e

sha256sum "$src/SIG_AlgorithmInstance.c" "$src/matrix.c" \
  "$src/SIG_AlgorithmInstance.h" >"$out/source.sha256"

echo "evidence written to $out"
