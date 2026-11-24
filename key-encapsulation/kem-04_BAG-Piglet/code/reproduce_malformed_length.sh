#!/usr/bin/env bash
set -euo pipefail

# Run from this directory after extracting the exact submitted ZIP into ./extracted.
test "$(sha256sum inputs/BAG-Piglet.zip | cut -d' ' -f1)" = \
  "31afe1f2f4e97ad77929d7855c7d9011d69755049d155c09be9339bc99b1d405"

declare -A pk=([128]=522 [256]=1573 [384]=2778 [512]=4158)
declare -A sk=([128]=16 [256]=32 [384]=48 [512]=64)
declare -A ss=([128]=16 [256]=32 [384]=48 [512]=64)

: > malformed_length_probe.result
for bits in 128 256 384 512; do
  base="extracted/Implementations/Reference_Implementation/bag_piglet${bits}"
  exe="malformed_length_probe_${bits}"
  gcc -std=gnu11 -O1 -g -fsanitize=address -fno-omit-frame-pointer \
    -DPROBE_PK_LEN="${pk[$bits]}" \
    -DPROBE_SK_LEN="${sk[$bits]}" \
    -DPROBE_SS_LEN="${ss[$bits]}" \
    -pthread \
    -I"$base/src/common" -I"$base/src/scheme" -I"$base/src/ffi" \
    -I"$base/src/rbc" -I"$base/src/kat" -I"$base/lib/api_pkc" \
    -I"$base/lib/randombytes" \
    "$base"/src/common/*.c "$base"/src/scheme/*.c \
    "$base"/src/ffi/*.c "$base"/src/rbc/*.c \
    "$base"/lib/api_pkc/*.c "$base"/lib/randombytes/randombytes.c \
    "$base"/src/kat/KEM_AlgorithmInstance.c malformed_length_probe.c \
    -o "$exe"

  set +e
  ASAN_OPTIONS=abort_on_error=0:exitcode=86 \
    "./$exe" >"${exe}.stdout" 2>"${exe}.stderr"
  rc=$?
  set -e
  first=$(rg -m1 'ERROR: AddressSanitizer|SUMMARY: AddressSanitizer' \
    "${exe}.stderr" || true)
  printf '%s exit=%s %s\n' "$bits" "$rc" "$first" | tee -a \
    malformed_length_probe.result
done
