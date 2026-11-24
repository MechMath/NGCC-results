#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
ref="$root/submission/Implementations/Reference_Implementation/BiT-512"
avx2="$root/submission/Implementations/Optimized_Implementation/BiT-512-avx2"
out="$root/experiments/oom-wrong-message"
mkdir -p "$out"

cc=${CC:-gcc}
"$cc" -std=c99 -O2 -I "$ref" \
  "$root/experiments/oom_wrong_message.c" \
  "$root/experiments/malloc_fault_wrap.c" \
  $(find "$ref" -maxdepth 1 -name '*.c' ! -name 'KAT_SIG.c' -print) \
  -Wl,--wrap=malloc \
  -o "$out/oom_wrong_message_reference"

"$cc" -O3 -march=x86-64 -mavx2 -mtune=native -flto \
  -fomit-frame-pointer -std=c99 -DASM_ALIASES -I "$avx2" \
  "$root/experiments/oom_wrong_message.c" \
  "$root/experiments/malloc_fault_wrap.c" \
  $(find "$avx2" -maxdepth 1 -name '*.c' ! -name 'KAT_SIG.c' -print) \
  $(find "$avx2" -maxdepth 1 -name '*.S' -print) \
  -Wl,--wrap=malloc \
  -o "$out/oom_wrong_message_avx2"

cd "$out"
"$out/oom_wrong_message_reference" reference-result.txt
"$out/oom_wrong_message_avx2" avx2-result.txt
cat reference-result.txt
cat avx2-result.txt
