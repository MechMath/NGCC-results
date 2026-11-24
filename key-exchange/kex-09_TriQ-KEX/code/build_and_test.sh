#!/usr/bin/env bash
set -euo pipefail

mkdir -p bin results

shared_sources=(
  upstream/shared/auxfunc.c
  upstream/shared/drng.c
  upstream/shared/src/common/code.c
  upstream/shared/src/common/crypto_memset.c
  upstream/shared/src/common/fft.c
  upstream/shared/src/common/kem.c
  upstream/shared/src/common/symmetric.c
  upstream/shared/src/ref/gf.c
  upstream/shared/src/ref/gf2x.c
  upstream/shared/src/ref/parsing.c
  upstream/shared/src/ref/reed_muller.c
  upstream/shared/src/ref/reed_solomon.c
  upstream/shared/src/ref/triq_pke.c
  upstream/shared/src/ref/vector.c
)

for profile in 128 256 384 512; do
  cc -O2 -std=c11 -Wall -Wextra \
    -I "upstream/TriQ-KEX-${profile}" \
    -I "upstream/TriQ-KEX-${profile}/src/common/triq-${profile}" \
    -I "upstream/TriQ-KEX-${profile}/src/ref/triq-${profile}" \
    -I upstream/shared \
    -I upstream/shared/src/common \
    -I upstream/shared/src/ref \
    state_retention_test.c \
    "upstream/TriQ-KEX-${profile}/KEX_AlgorithmInstance.c" \
    "${shared_sources[@]}" \
    -o "bin/state_retention_test_${profile}"

  "bin/state_retention_test_${profile}" | tee "results/state_retention_test_${profile}.txt"
done

sha256sum bin/state_retention_test_* results/*.txt > results/SHA256SUMS
