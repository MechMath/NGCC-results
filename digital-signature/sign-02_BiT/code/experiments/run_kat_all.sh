#!/usr/bin/env bash
set -euo pipefail

slot=$(cd "$(dirname "$0")/.." && pwd)
src_root="$slot/input/extracted/Implementations"
out_root="$slot/results/kat"
mkdir -p "$out_root"

run_one() {
    local kind=$1
    local name=$2
    local vec=$3
    local dir="$src_root/$kind/$name"
    make -C "$dir" clean >/dev/null
    make -C "$dir" -j2
    (
        cd "$dir"
        ./KAT_SIG > "$out_root/$name.stdout" 2> "$out_root/$name.stderr"
        cp "output/KAT_SIG_$vec.txt" "$out_root/$name.txt"
    )
    sha256sum "$out_root/$name.txt"
}

run_one Reference_Implementation BiT-128 BiT-128
run_one Reference_Implementation BiT-256 BiT-256
run_one Reference_Implementation BiT-512 BiT-512
run_one Optimized_Implementation BiT-128-avx2 BiT-128
run_one Optimized_Implementation BiT-256-avx2 BiT-256
run_one Optimized_Implementation BiT-512-avx2 BiT-512

for bits in 128 256 512; do
    cmp "$out_root/BiT-$bits.txt" "$slot/input/extracted/Test_Vectors/KAT_SIG_BiT-$bits.txt"
    cmp "$out_root/BiT-$bits-avx2.txt" "$slot/input/extracted/Test_Vectors/KAT_SIG_BiT-$bits.txt"
done
echo "kat_reference_and_avx2_match_submitted_vectors=1"
