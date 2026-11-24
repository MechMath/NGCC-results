#!/usr/bin/env bash
set -euo pipefail

commit=dc66c6cb3c06e75bdea0048e21fa4e13c63f00af
base="https://ghproxy.net/https://raw.githubusercontent.com/ngcc-dev/ngcc-harness/${commit}/kex-09/TriQ-KEX/Implementations/Reference_Implementation"

shared_top_files=(
  auxfunc.c
  auxfunc.h
  drng.c
  drng.h
)
common_files=(
  code.c code.h crypto_memset.c crypto_memset.h fft.c fft.h
  kem.c reed_muller.h symmetric.c symmetric.h
)
ref_files=(
  data_structures.h gf.c gf.h gf2x.c gf2x.h parsing.c parsing.h
  reed_muller.c reed_solomon.c triq_pke.c triq_pke.h vector.c vector.h
)

mkdir -p upstream/shared/src/common upstream/shared/src/ref
for file in "${shared_top_files[@]}"; do
  curl -fsSL --max-time 60 "$base/TriQ-KEX-128/${file}" -o "upstream/shared/${file}"
done
for file in "${common_files[@]}"; do
  curl -fsSL --max-time 60 "$base/TriQ-KEX-128/src/common/${file}" \
    -o "upstream/shared/src/common/${file}"
done
for file in "${ref_files[@]}"; do
  curl -fsSL --max-time 60 "$base/TriQ-KEX-128/src/ref/${file}" \
    -o "upstream/shared/src/ref/${file}"
done

for profile in 128 256 384 512; do
  root="upstream/TriQ-KEX-${profile}"
  mkdir -p "$root/src/common/triq-${profile}" "$root/src/ref/triq-${profile}"

  for file in KAT_KEX.c KEX_AlgorithmInstance.c KEX_AlgorithmInstance.h; do
    curl -fsSL --max-time 60 "$base/TriQ-KEX-${profile}/${file}" -o "$root/${file}"
  done

  for file in api.h; do
    curl -fsSL --max-time 60 "$base/TriQ-KEX-${profile}/src/common/triq-${profile}/${file}" \
      -o "$root/src/common/triq-${profile}/${file}"
  done
  for file in parameters.h reed_solomon.h; do
    curl -fsSL --max-time 60 "$base/TriQ-KEX-${profile}/src/ref/triq-${profile}/${file}" \
      -o "$root/src/ref/triq-${profile}/${file}"
  done
done

find upstream -type f ! -name SHA256SUMS -print0 |
  sort -z | xargs -0 sha256sum > upstream/SHA256SUMS
