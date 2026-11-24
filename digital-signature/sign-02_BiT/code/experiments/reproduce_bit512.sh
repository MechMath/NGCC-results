#!/usr/bin/env bash
set -uo pipefail
export LC_ALL=C
export SOURCE_DATE_EPOCH=0

root="$(cd "$(dirname "$0")/.." && pwd)"
archive="$root/BiT.zip"
expected_zip=698fbe834279a4100a66c20f3e0b634c738e1150936acf74b55efc6db6975e8d

mkdir -p "$root/results" "$root/build"
printf 'timestamp_utc=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$root/results/environment.txt"
printf 'uname=%s\n' "$(uname -a)" >> "$root/results/environment.txt"
printf 'gcc=%s\n' "$(gcc --version | head -1)" >> "$root/results/environment.txt"
printf 'glibc=%s\n' "$(getconf GNU_LIBC_VERSION)" >> "$root/results/environment.txt"
printf 'cpu=%s\n' "$(lscpu | sed -n 's/^Model name:[[:space:]]*//p' | head -1)" >> "$root/results/environment.txt"

echo "zip_sha256=$(sha256sum "$archive" | awk '{print $1}')" | tee "$root/results/source-hashes.txt"
if [ "$(sha256sum "$archive" | awk '{print $1}')" != "$expected_zip" ]; then
  echo "ZIP checksum mismatch" | tee -a "$root/results/failures.txt"
  exit 10
fi
sha256sum "$root/experiments/oom_wrong_message.c" \
          "$root/experiments/malloc_fault_wrap.c" \
          "$root/experiments/reproduce_bit512.sh" >> "$root/results/source-hashes.txt"

gcc -shared -fPIC -O2 -Wall -Wextra \
  "$root/experiments/malloc_fault_wrap.c" -ldl \
  -o "$root/build/malloc_fault_wrap.so"

for impl in \
  "reference:Implementations/Reference_Implementation/BiT-512" \
  "avx2:Implementations/Optimized_Implementation/BiT-512-avx2"
do
  name=${impl%%:*}
  rel=${impl#*:}
  src="$root/extracted/$rel"
  out="$root/build/oom-$name"
  rm -f "$out"
  csrc=()
  for f in "$src"/*.c; do
    [ "$(basename "$f")" = KAT_SIG.c ] && continue
    [ "$(basename "$f")" = packing.c ] && continue
    csrc+=("$f")
  done
  csrc+=("$src/packing.c")
  if [ "$name" = avx2 ]; then
    gcc -O3 -march=x86-64 -mavx2 -mtune=native -flto -fomit-frame-pointer \
      -std=c99 -Wpedantic -Wall -Wextra -DASM_ALIASES -I"$src" \
      "$root/experiments/oom_wrong_message.c" "${csrc[@]}" \
      "$src/f1600x4.S" "$src/ntt.S" "$src/intt.S" "$src/pointwise.S" \
      -o "$out" 2> "$root/results/$name-build.log"
  else
    gcc -std=c99 -Wpedantic -Wall -Wextra -O2 -I"$src" \
      "$root/experiments/oom_wrong_message.c" "${csrc[@]}" \
      -o "$out" 2> "$root/results/$name-build.log"
  fi
  build_rc=$?
  echo "${name}_build_rc=$build_rc" | tee -a "$root/results/failures.txt"
  if [ $build_rc -ne 0 ]; then continue; fi
  LD_PRELOAD="$root/build/malloc_fault_wrap.so" "$out" \
    > "$root/results/$name.log" 2>&1
  run_rc=$?
  echo "${name}_run_rc=$run_rc" | tee -a "$root/results/failures.txt"
  cat "$root/results/$name.log"
  sha256sum "$out" >> "$root/results/source-hashes.txt"
done

sha256sum "$root/results/"*.log "$root/results/source-hashes.txt" \
  > "$root/results/output-hashes.txt"
