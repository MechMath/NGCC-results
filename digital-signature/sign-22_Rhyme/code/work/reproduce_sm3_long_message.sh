#!/usr/bin/env bash
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/.." && pwd)"
zip_root="$root/original/rhyme/Implementations and Test_Vectors/Implementations"
harness="$here/sm3_longmsg_harness.c"

compile_reference_sm3() {
    local mode="$1"
    local dir="$zip_root/Reference_Implementation/Rhyme-SM3/Rhyme-SM3-$mode"
    local out="$here/sm3_longmsg_harness_$mode"
    gcc -O2 -std=c99 -I"$dir" -I"$dir/include" -I"$dir/src/keygen" \
        -DRHYME_NO_AES -DRHYME_MODE="$mode" \
        -DALGORITHM_INSTANCE="\"Rhyme-SM3-$mode\"" \
        -o "$out" "$harness" \
        "$dir/src/poly.c" "$dir/src/ntt.c" "$dir/src/ntt_tables.c" \
        "$dir/src/sampler.c" "$dir/src/encoding.c" "$dir/src/packing.c" \
        "$dir/src/sign.c" "$dir/src/zpntt.c" "$dir/src/symmetric-shake.c" \
        "$dir/sm3.c" "$dir/sm3_xof.c" "$dir/rhyme_xof.c" \
        "$dir/src/keygen/kg_main.c" "$dir/src/keygen/kg_solver.c" \
        "$dir/src/keygen/kg_zint.c" "$dir/src/keygen/kg_ntt.c" \
        "$dir/src/keygen/kg_primes.c" "$dir/src/randombytes.c" \
        "$dir/auxfunc.c" "$dir/SIG_AlgorithmInstance.c" -lm
    "$out"
}

compile_optimized_sm3_128() {
    local mode=128
    local dir="$zip_root/Optimized_Implementation/Rhyme-SM3/Rhyme-SM3-$mode"
    local out="$here/sm3_longmsg_harness_opt$mode"
    gcc -O3 -march=native -mavx2 -std=c99 \
        -I"$dir" -I"$dir/include" -I"$dir/src/keygen" \
        -DRHYME_NO_AES -DRHYME_MODE="$mode" -DUSE_AVX2_SM3 \
        -DALGORITHM_INSTANCE="\"Rhyme-SM3-$mode\"" \
        -o "$out" "$harness" \
        "$dir/src/poly.c" "$dir/src/ntt.c" "$dir/src/ntt_tables.c" \
        "$dir/src/sampler.c" "$dir/src/encoding.c" "$dir/src/packing.c" \
        "$dir/src/sign.c" "$dir/src/zpntt.c" "$dir/src/symmetric-shake.c" \
        "$dir/sm3.c" "$dir/sm3_xof.c" "$dir/simd/sm3_avx2.c" \
        "$dir/rhyme_xof.c" \
        "$dir/src/keygen/kg_main.c" "$dir/src/keygen/kg_solver.c" \
        "$dir/src/keygen/kg_zint.c" "$dir/src/keygen/kg_ntt.c" \
        "$dir/src/keygen/kg_primes.c" "$dir/src/randombytes.c" \
        "$dir/auxfunc.c" "$dir/SIG_AlgorithmInstance.c" -lm
    "$out"
}

compile_shake_control() {
    local mode=128
    local dir="$zip_root/Reference_Implementation/Rhyme-SHAKE/Rhyme-SHAKE-$mode"
    local out="$here/sm3_longmsg_harness_shake$mode"
    gcc -O2 -std=c99 -I"$dir" -I"$dir/include" -I"$dir/src/keygen" \
        -DRHYME_NO_AES -DRHYME_MODE="$mode" \
        -DALGORITHM_INSTANCE="\"Rhyme-SHAKE-$mode\"" \
        -o "$out" "$harness" \
        "$dir/src/poly.c" "$dir/src/ntt.c" "$dir/src/ntt_tables.c" \
        "$dir/src/sampler.c" "$dir/src/encoding.c" "$dir/src/packing.c" \
        "$dir/src/sign.c" "$dir/src/zpntt.c" "$dir/src/symmetric-shake.c" \
        "$dir/src/fips202.c" "$dir/rhyme_xof.c" \
        "$dir/src/keygen/kg_main.c" "$dir/src/keygen/kg_solver.c" \
        "$dir/src/keygen/kg_zint.c" "$dir/src/keygen/kg_ntt.c" \
        "$dir/src/keygen/kg_primes.c" "$dir/src/randombytes.c" \
        "$dir/auxfunc.c" "$dir/SIG_AlgorithmInstance.c" -lm
    "$out"
}

for mode in 128 256 384 512; do
    compile_reference_sm3 "$mode"
done
compile_optimized_sm3_128
compile_shake_control
