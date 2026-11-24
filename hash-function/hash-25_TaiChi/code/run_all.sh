#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p artifacts
python3 -m py_compile src/taichi_ref.py tests/test_reference.py
python3 tests/test_reference.py > artifacts/reference_checks.json
sha256sum \
  spec/hash-25-spec.pdf \
  src/taichi_ref.py \
  tests/test_reference.py \
  artifacts/reference_checks.json | tee artifacts/SHA256SUMS
