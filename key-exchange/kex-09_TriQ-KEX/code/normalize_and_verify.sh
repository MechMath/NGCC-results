#!/usr/bin/env bash
set -euo pipefail

mkdir -p results

{
  for profile in 128 256 384 512; do
    printf 'wrapper %s ' "$profile"
    perl -0777 -pe \
      's/static const unsigned char kdf_s\[SEED_BYTES\] = \{.*?\};/static const unsigned char kdf_s[SEED_BYTES] = { PLACEHOLDER };/s' \
      "upstream/TriQ-KEX-${profile}/KEX_AlgorithmInstance.c" |
      sha256sum | cut -d' ' -f1
  done

  for profile in 128 256 384 512; do
    printf 'header %s ' "$profile"
    perl -0777 -pe \
      's/#define ALGORITHM_INSTANCE "[^"]+"/#define ALGORITHM_INSTANCE "PLACEHOLDER"/' \
      "upstream/TriQ-KEX-${profile}/KEX_AlgorithmInstance.h" |
      sed 's/^\xEF\xBB\xBF//; s/\r$//' |
      sha256sum | cut -d' ' -f1
  done
} | tee results/normalized_source_hashes.txt

test "$(cut -d' ' -f3 results/normalized_source_hashes.txt | sed -n '1,4p' | uniq | wc -l)" -eq 1
test "$(cut -d' ' -f3 results/normalized_source_hashes.txt | sed -n '5,8p' | uniq | wc -l)" -eq 1
