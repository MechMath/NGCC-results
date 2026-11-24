#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
srcroot=${1:?usage: run.sh SRC_TREE OUTPUT_ROOT}
out=${2:?usage: run.sh SRC_TREE OUTPUT_ROOT}
extra=${EXTRA_CFLAGS:-}
mkdir -p "$out/bin"

gcc -std=c99 -O2 -Wall -Wextra -Wpedantic \
  $extra -DFACTODSA_SO_BUILD -I"$srcroot" \
  -o "$out/bin/fork_drng" "$root/fork_drng/fork_drng.c" \
  "$srcroot/SIG_AlgorithmInstance.c" "$srcroot/auxfunc.c" "$srcroot/drng.c"
sha256sum "$srcroot/SIG_AlgorithmInstance.c" "$srcroot/auxfunc.c" \
  "$srcroot/drng.c" "$root/fork_drng/fork_drng.c" > "$out/source_hashes.txt"
sha256sum "$out/bin/fork_drng" > "$out/binary_sha256.txt"

for mode in fork-keygen fork-sign fork-reseed sequential; do
  mkdir -p "$out/$mode"
  "$out/bin/fork_drng" "$mode" "$out/$mode" | tee "$out/$mode/harness.txt"
done

mkdir -p "$out/startup-a" "$out/startup-b"
"$out/bin/fork_drng" startup "$out/startup-a" | tee "$out/startup-a/harness.txt"
"$out/bin/fork_drng" startup "$out/startup-b" | tee "$out/startup-b/harness.txt"

python3 "$root/fork_drng/summarize.py" "$out"
