#!/bin/sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$ROOT"

EXPECTED_ZIP=698fbe834279a4100a66c20f3e0b634c738e1150936acf74b55efc6db6975e8d
EXPECTED_SPEC=28e942ee1baa7b686271420d56bea370c65891b4b57ef4045424f8a52dd0ccca

test "$(sha256sum original/BiT.zip | awk '{print $1}')" = "$EXPECTED_ZIP"
test "$(sha256sum original/sign-02-spec.pdf | awk '{print $1}')" = "$EXPECTED_SPEC"

rm -rf extracted/BiT
mkdir -p extracted/BiT experiments/bin experiments/out
python3 -m zipfile -e original/BiT.zip extracted/BiT

sh experiments/build.sh > experiments/out/build.log 2>&1

make -C extracted/BiT/Implementations/Reference_Implementation/BiT-128 correctness \
  > experiments/out/reference-make-correctness.stdout 2>&1
make -C extracted/BiT/Implementations/Optimized_Implementation/BiT-128-avx2 correctness \
  > experiments/out/avx2-make-correctness.stdout 2>&1

experiments/bin/bit128_reference selftest experiments/out/reference-selftest \
  > experiments/out/reference-selftest.stdout
experiments/bin/bit128_avx2 selftest experiments/out/avx2-selftest \
  > experiments/out/avx2-selftest.stdout

experiments/bin/bit128_reference generate \
  experiments/out/bit128-pk-divergence.tuple \
  experiments/out/bit128-pk-divergence.tuple.sha256 \
  > experiments/out/bit128_reference-generate.stdout
experiments/bin/bit128_avx2 generate \
  experiments/out/bit128-pk-divergence-avx.tuple \
  experiments/out/bit128-pk-divergence-avx.tuple.sha256 \
  > experiments/out/bit128_avx2-generate.stdout
cmp experiments/out/bit128-pk-divergence.tuple \
  experiments/out/bit128-pk-divergence-avx.tuple
experiments/bin/bit128_reference verify experiments/out/bit128-pk-divergence.tuple \
  > experiments/out/bit128_reference-verify.stdout
experiments/bin/bit128_avx2 verify experiments/out/bit128-pk-divergence.tuple \
  > experiments/out/bit128_avx2-verify.stdout

cmp -l experiments/out/bit128-pk-divergence.tuple.pk.honest \
  experiments/out/bit128-pk-divergence.tuple.pk.mutated \
  > experiments/out/pk-byte-differences.txt || true
cmp -l experiments/out/bit128-pk-divergence.tuple.sk.original \
  experiments/out/bit128-pk-divergence.tuple.sk.rebound \
  > experiments/out/sk-byte-differences.txt || true

python3 experiments/decoder_analysis.py > experiments/out/decoder-analysis.txt

sha256sum \
  original/BiT.zip \
  original/sign-02-spec.pdf \
  extracted/BiT/"Algorithm specifications.pdf" \
  extracted/BiT/Implementations/Reference_Implementation/BiT-128/packing.c \
  extracted/BiT/Implementations/Optimized_Implementation/BiT-128-avx2/packing.c \
  extracted/BiT/Implementations/Reference_Implementation/BiT-128/sign.c \
  extracted/BiT/Implementations/Optimized_Implementation/BiT-128-avx2/sign.c \
  > experiments/out/source-hashes.txt

sha256sum \
  experiments/out/bit128-pk-divergence.tuple \
  experiments/out/bit128-pk-divergence-avx.tuple \
  experiments/out/bit128-pk-divergence.tuple.pk.honest \
  experiments/out/bit128-pk-divergence.tuple.pk.mutated \
  experiments/out/bit128-pk-divergence.tuple.sig.rebound \
  experiments/out/bit128-pk-divergence.tuple.msg \
  experiments/out/bit128-pk-divergence.tuple.sk.original \
  experiments/out/bit128-pk-divergence.tuple.sk.rebound \
  experiments/bin/bit128_reference \
  experiments/bin/bit128_avx2 \
  > experiments/out/artifact-sha256.txt

printf 'reproduction complete\n'
