#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$root"

core_ref='cbd.c fips202.c poly.c reduce.c precomp.c ntt.c polyvec.c owcpa.c kem.c verify.c hashkdf.c gen_a.c pack.c randombytes.c'
core_opt='cbd.c fips202.c fips202x4.c poly.c precomp.c ntt.c polyvec.c owcpa.c kem.c verify.c hashkdf.c genmatrix.c pack.c randombytes.c'

names='I II III'
index=0
for name in $names; do
  index=$((index + 1))
  src="original/Implementations/Reference_Implementation/Aigis-Enc+-${name}"
  # shellcheck disable=SC2086
  gcc -O2 -std=c99 -w -DPARAMS="$index" -DUSE_SHA3 -I"$src" \
    $(for f in $core_ref; do printf '%s/%s ' "$src" "$f"; done) \
    attack_first_bit.c -o "attack_first_bit_ref_${name}"
  "./attack_first_bit_ref_${name}" 128 > "attack_first_bit_ref_${name}.out"
done

index=0
for name in $names; do
  index=$((index + 1))
  src="original/Implementations/Optimized_Implementation/avx2/Aigis-Enc+-${name}"
  gcc -c -O2 -mavx2 -mbmi2 -mpopcnt -maes -march=native -std=c99 -w \
    "$src/keccak4x/KeccakP-1600-times4-SIMD256.c" -o "keccak_opt_${index}.o"
  # shellcheck disable=SC2086
  gcc -O2 -mavx2 -mbmi2 -mpopcnt -maes -march=native -std=c99 -w \
    -DPARAMS="$index" -DUSE_SHA3 -DKDF_AVX -I"$src" \
    $(for f in $core_opt; do printf '%s/%s ' "$src" "$f"; done) \
    "keccak_opt_${index}.o" attack_first_bit.c -o "attack_first_bit_avx2_${name}"
  "./attack_first_bit_avx2_${name}" 128 > "attack_first_bit_avx2_${name}.out"
done

src=corrected/reference-I
# shellcheck disable=SC2086
gcc -O2 -std=c99 -w -DPARAMS=1 -DUSE_SHA3 -I"$src" \
  $(for f in $core_ref; do printf '%s/%s ' "$src" "$f"; done) \
  attack_first_bit.c -o attack_corrected_ref_I
./attack_corrected_ref_I 128 > attack_corrected_ref_I.out || true

src=corrected/avx2-I
# shellcheck disable=SC2086
gcc -O2 -mavx2 -mbmi2 -mpopcnt -maes -march=native -std=c99 -w \
  -DPARAMS=1 -DUSE_SHA3 -DKDF_AVX -I"$src" \
  $(for f in $core_opt; do printf '%s/%s ' "$src" "$f"; done) \
  keccak_opt_1.o attack_first_bit.c -o attack_corrected_opt_I
./attack_corrected_opt_I 128 > attack_corrected_opt_I.out || true

printf '%s\n' 'all attack runs completed'
