#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "$0")" && pwd)"
cd "$root_dir"

case_dir=repro_cs
mkdir -p "$case_dir"
python3 -m zipfile -e CS.zip "$case_dir"

for bits in 128 256 512; do
  src="$case_dir/Implementations/Reference_Implementation/CS-$bits"

  # Build-only fixes for the Linux/GCC toolchain. Neither changes CS logic.
  # 1. ntt.c includes NTT.h while the archive member is ntt.h.
  if [ ! -e "$src/NTT.h" ]; then
    ln -s ntt.h "$src/NTT.h"
  fi
  # 2. ntt.c defines MultiplyNTT static, but ntt.h declares it external.
  sed -i 's/^void MultiplyNTT(/static void MultiplyNTT(/' "$src/ntt.h"

  common_flags=(-O2 -std=c11 -fcommon -w)
  gcc "${common_flags[@]}" -I"$src" \
    $(find "$src" -maxdepth 1 -name '*.c' ! -name 'KAT_SIG.c' -print) \
    length_confusion_test.c -o "length_confusion_test_$bits"
  "./length_confusion_test_$bits" > "length_confusion_test_$bits.log"

  gcc "${common_flags[@]}" -I"$src" \
    $(find "$src" -maxdepth 1 -name '*.c' ! -name 'KAT_SIG.c' -print) \
    length_confusion_empty_test.c -o "length_confusion_empty_test_$bits"
  "./length_confusion_empty_test_$bits" > "length_confusion_empty_test_$bits.log"

  mkdir -p "kat-run-$bits"
  gcc "${common_flags[@]}" -I"$src" \
    $(find "$src" -maxdepth 1 -name '*.c' -print) -o "kat-run-$bits/kat$bits"
  (cd "kat-run-$bits" && "./kat$bits" > run.log 2>&1)
  cmp "kat-run-$bits/output/KAT_SIG_CS_$bits.txt" \
      "original_cs/Test_Vectors/KAT_SIG_CS_$bits.txt"
  sha256sum "kat-run-$bits/output/KAT_SIG_CS_$bits.txt" \
            "original_cs/Test_Vectors/KAT_SIG_CS_$bits.txt" \
    >> kat_verification.log
done

# The crash control intentionally returns status 139.
src="$case_dir/Implementations/Reference_Implementation/CS-128"
gcc -O2 -std=c11 -fcommon -w -I"$src" \
  $(find "$src" -maxdepth 1 -name '*.c' ! -name 'KAT_SIG.c' -print) \
  length_overflow_crash_test.c -o length_overflow_crash_test
set +e
./length_overflow_crash_test > length_overflow_crash_test.log 2>&1
status=$?
set -e
printf 'exit_status=%d\n' "$status" >> length_overflow_crash_test.log

objdump -d -Mintel length_confusion_test_128 > sig_length_disassembly.txt
