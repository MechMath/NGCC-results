#!/usr/bin/env bash
set -euo pipefail

./concurrency_probe_ref128 > concurrency_ref128.log
cp concurrent_duplicate_key.bin duplicate_ref128.bin
./concurrency_probe_avx128 > concurrency_avx128.log
cp concurrent_duplicate_key.bin duplicate_avx128.bin
./concurrency_probe_ref256 > concurrency_ref256.log
cp concurrent_duplicate_key.bin duplicate_ref256.bin
./concurrency_probe_avx256 > concurrency_avx256.log
cp concurrent_duplicate_key.bin duplicate_avx256.bin

sha256sum duplicate_*.bin
