#!/usr/bin/env bash
set -u

root=${1:-source/Implementations}
out=results/matrix
mkdir -p "$out"

gcc -shared -fPIC -O2 -fno-builtin-malloc experiments/malloc_fault.c \
  -o "$out/malloc_fault.so" 2>"$out/malloc_fault.build.err"

for impl in Reference_Implementation/BiT-512 Optimized_Implementation/BiT-512-avx2; do
  src="$root/$impl"
  tag=$(basename "$impl")
  for opt in O0 O2; do
    if [[ "$impl" == Optimized* ]]; then
      common=(-std=c99 -mavx2 -DASM_ALIASES "-$opt")
      asm=("$src/f1600x4.S" "$src/ntt.S" "$src/intt.S" "$src/pointwise.S")
    else
      common=(-std=c99 "-$opt")
      asm=()
    fi
    exe="$out/${tag}-gcc-${opt}"
    printf 'BUILD %s %s\n' "$tag" "$opt"
    gcc "${common[@]}" -fno-builtin-malloc -I"$src" experiments/oom_probe.c \
      $(find "$src" -maxdepth 1 -name '*.c' ! -name 'KAT_SIG.c' | sort) \
      "${asm[@]}" "$PWD/$out/malloc_fault.so" \
      -Wl,-rpath,"$PWD/$out" -o "$exe" 2>"$out/${tag}-gcc-${opt}.build.err"
    printf '%s\n' "$?" >"$out/${tag}-gcc-${opt}.build.rc"
    if [[ ! -x "$exe" ]]; then
      continue
    fi
    for mode in 1 2 3; do
      LD_PRELOAD="$PWD/$out/malloc_fault.so" "$exe" "$mode" \
        >"$out/${tag}-gcc-${opt}-mode${mode}.log" \
        2>"$out/${tag}-gcc-${opt}-mode${mode}.err"
      printf '%s\n' "$?" >"$out/${tag}-gcc-${opt}-mode${mode}.rc"
    done
  done
done
