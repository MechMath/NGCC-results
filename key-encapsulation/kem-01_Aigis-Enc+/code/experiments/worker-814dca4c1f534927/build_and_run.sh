#!/usr/bin/env bash
set -euo pipefail

scope_dir="$(cd "$(dirname "$0")" && pwd)"
original_root="${scope_dir}/original/Implementations/Reference_Implementation"
out="${scope_dir}/experiments"
mkdir -p "${out}/bin" "${out}/logs" "${out}/objects"

common_sources=(
  cbd.c fips202.c poly.c reduce.c precomp.c ntt.c polyvec.c owcpa.c
  verify.c hashkdf.c gen_a.c pack.c randombytes.c
)

{
  date -u +'utc=%Y-%m-%dT%H:%M:%SZ'
  uname -a
  gcc --version | head -1
  lscpu | grep -E '^(Architecture|Model name|Flags):'
  sha256sum "${original_root}/Aigis-Enc+-I/kem.c"
} > "${out}/environment.txt"

for pset in 1 2 3; do
  case "${pset}" in
    1) name=I ;;
    2) name=II ;;
    3) name=III ;;
  esac
  src="${original_root}/Aigis-Enc+-${name}"
  srcs=()
  for f in "${common_sources[@]}"; do
    srcs+=("${src}/${f}")
  done

  gcc -std=c99 -DPARAMS="${pset}" -DUSE_SHA3 -I"${src}" -I"${src}/kat_test" \
    "${srcs[@]}" "${src}/kem.c" "${src}/kat_test/KEM_AlgorithmInstance.c" \
    "${scope_dir}/harness_mdkem.c" \
    -O3 -fomit-frame-pointer -march=native -fPIC \
    -Wno-incompatible-pointer-types -Wall -Wextra \
    -o "${out}/bin/original_p${pset}_ordinary"

  gcc -std=c99 -DPARAMS="${pset}" -DUSE_SHA3 -I"${src}" -I"${src}/kat_test" \
    "${srcs[@]}" "${src}/kem.c" "${src}/kat_test/KEM_AlgorithmInstance.c" \
    "${scope_dir}/harness_mdkem.c" \
    -O1 -g -fno-omit-frame-pointer -march=native \
    -fsanitize=address,undefined -fno-sanitize-recover=all \
    -Wno-incompatible-pointer-types -Wall -Wextra \
    -o "${out}/bin/original_p${pset}_asan_ubsan"

  gcc -std=c99 -DPARAMS="${pset}" -DUSE_SHA3 -I"${src}" -I"${src}/kat_test" \
    "${srcs[@]}" "${scope_dir}/oracle/kem_oracle.c" \
    "${src}/kat_test/KEM_AlgorithmInstance.c" "${scope_dir}/harness_mdkem.c" \
    -O1 -g -fno-omit-frame-pointer -march=native \
    -fsanitize=address,undefined -fno-sanitize-recover=all \
    -Wno-incompatible-pointer-types -Wall -Wextra \
    -o "${out}/bin/oracle_p${pset}_asan_ubsan"

done

for pset in 1 2 3; do
  {
    echo "=== original p${pset} standard ordinary ==="
    "${out}/bin/original_p${pset}_ordinary" standard
  } > "${out}/logs/p${pset}_standard_ordinary.log" 2>&1 || true

  {
    echo "=== original p${pset} CCA stress ordinary ==="
    set +e
    "${out}/bin/original_p${pset}_ordinary" cca 100
    rc=$?
    set -e
    echo "process_exit=$rc"
  } > "${out}/logs/p${pset}_cca_100_ordinary.log" 2>&1

  {
    echo "=== original p${pset} standard ASan/UBSan ==="
    set +e
    "${out}/bin/original_p${pset}_asan_ubsan" standard
    rc=$?
    set -e
    echo "process_exit=$rc"
  } > "${out}/logs/p${pset}_standard_asan_ubsan.log" 2>&1

  {
    echo "=== original p${pset} mdkem ordinary ==="
    set +e
    "${out}/bin/original_p${pset}_ordinary" mdkem 20
    rc=$?
    set -e
    echo "process_exit=$rc"
  } > "${out}/logs/p${pset}_mdkem_ordinary.log" 2>&1

  {
    echo "=== original p${pset} mdkem ASan/UBSan ==="
    set +e
    "${out}/bin/original_p${pset}_asan_ubsan" mdkem 20
    rc=$?
    set -e
    echo "process_exit=$rc"
  } > "${out}/logs/p${pset}_mdkem_asan_ubsan.log" 2>&1

  {
    echo "=== corrected oracle p${pset} mdkem ASan/UBSan ==="
    set +e
    "${out}/bin/oracle_p${pset}_asan_ubsan" mdkem 5
    rc=$?
    set -e
    echo "process_exit=$rc"
  } > "${out}/logs/p${pset}_mdkem_oracle_asan_ubsan.log" 2>&1
done

avx_root="${scope_dir}/original/Implementations/Optimized_Implementation/avx2"
avx_common=(
  cbd.c fips202.c fips202x4.c poly.c precomp.c ntt.c polyvec.c owcpa.c
  verify.c hashkdf.c genmatrix.c pack.c randombytes.c
  keccak4x/KeccakP-1600-times4-SIMD256.o
)
for pset in 1 2 3; do
  case "${pset}" in
    1) name=I ;;
    2) name=II ;;
    3) name=III ;;
  esac
  src="${avx_root}/Aigis-Enc+-${name}"
  srcs=()
  for f in "${avx_common[@]}"; do
    srcs+=("${src}/${f}")
  done

  gcc -std=c99 -DPARAMS="${pset}" -DUSE_SHA3 -DKDF_AVX -I"${src}" \
    "${srcs[@]}" "${src}/kem.c" "${src}/KEM_AlgorithmInstance.c" \
    "${scope_dir}/harness_mdkem.c" \
    -O3 -fomit-frame-pointer -mavx2 -mbmi2 -mpopcnt -maes -march=native \
    -mtune=native -Wno-incompatible-pointer-types -Wall -Wextra \
    -o "${out}/bin/avx2_p${pset}_ordinary"

  gcc -std=c99 -DPARAMS="${pset}" -DUSE_SHA3 -DKDF_AVX -I"${src}" \
    "${srcs[@]}" "${src}/kem.c" "${src}/KEM_AlgorithmInstance.c" \
    "${scope_dir}/harness_mdkem.c" \
    -O1 -g -fno-omit-frame-pointer -mavx2 -mbmi2 -mpopcnt -maes -march=native \
    -fsanitize=address,undefined -fno-sanitize-recover=all \
    -Wno-incompatible-pointer-types -Wall -Wextra \
    -o "${out}/bin/avx2_p${pset}_asan_ubsan"

  {
    echo "=== original AVX2 p${pset} standard ordinary ==="
    "${out}/bin/avx2_p${pset}_ordinary" standard
  } > "${out}/logs/avx2_p${pset}_standard_ordinary.log" 2>&1 || true

  {
    echo "=== original AVX2 p${pset} CCA stress ordinary ==="
    set +e
    "${out}/bin/avx2_p${pset}_ordinary" cca 100
    rc=$?
    set -e
    echo "process_exit=$rc"
  } > "${out}/logs/avx2_p${pset}_cca_100_ordinary.log" 2>&1

  {
    echo "=== original AVX2 p${pset} mdkem ASan/UBSan ==="
    set +e
    "${out}/bin/avx2_p${pset}_asan_ubsan" mdkem 5
    rc=$?
    set -e
    echo "process_exit=$rc"
  } > "${out}/logs/avx2_p${pset}_mdkem_asan_ubsan.log" 2>&1
done

sha256sum "${out}"/bin/* > "${out}/bin.sha256"
sha256sum "${out}"/logs/* > "${out}/logs.sha256"
