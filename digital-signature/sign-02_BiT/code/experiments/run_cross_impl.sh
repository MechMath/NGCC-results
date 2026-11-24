#!/usr/bin/env bash
set -euo pipefail

slot=$(cd "$(dirname "$0")/.." && pwd)
src_root="$slot/input/extracted/Implementations"
out_root="$slot/results/cross_impl_oom"
mkdir -p "$out_root" "$slot/build"

run_one() {
    local kind=$1
    local name=$2
    local dir="$src_root/$kind/$name"
    local log="$out_root/$name.log"
    local bin="$slot/build/$name-oom"
    local -a csrc
    local -a asrc=()
    local -a flags=(-std=c99 -O2 -g -Wall -Wextra -I"$dir" -I"$slot/experiments")

    mapfile -t csrc < <(find "$dir" -maxdepth 1 -name '*.c' ! -name 'KAT_SIG.c' -print | sort)
    if [[ "$kind" == "Optimized_Implementation" ]]; then
        flags+=(-mavx2 -DASM_ALIASES)
        asrc=("$dir/f1600x4.S" "$dir/ntt.S" "$dir/intt.S" "$dir/pointwise.S")
    fi

    gcc "${flags[@]}" "$slot/experiments/oom_cross_impl.c" \
        "$slot/experiments/malloc_fault_wrap.c" "${csrc[@]}" "${asrc[@]}" \
        -Wl,--wrap=malloc -o "$bin"
    {
        echo "implementation=$name"
        echo "kind=$kind"
        echo "binary_sha256=$(sha256sum "$bin" | awk '{print $1}')"
        echo "source_hashes:"
        (cd "$dir" && find . -maxdepth 1 \( -name '*.c' -o -name '*.h' -o -name '*.S' \) -print0 |
            sort -z | xargs -0 sha256sum)
        echo "run:"
        "$bin"
    } 2>&1 | tee "$log"
}

run_one Reference_Implementation BiT-128
run_one Reference_Implementation BiT-256
run_one Reference_Implementation BiT-512
run_one Optimized_Implementation BiT-128-avx2
run_one Optimized_Implementation BiT-256-avx2
run_one Optimized_Implementation BiT-512-avx2
