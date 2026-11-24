#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
src="$root/original/submission/Implementations/Reference_Implementation/GreatWall128s"
out="$root/evidence/orch-default-drng"
build="$(mktemp -d)"
trap 'rm -rf "$build"' EXIT
: > "$out/compile.stderr"

sources=(
  SIG_AlgorithmInstance.c
  drng.c
  api.c
  aes.c
  aes_impl.c
  block.c
  block_impl.c
  faest.c
  greatwall.c
  greatwall-128-matrix.c
  greatwall_impl.c
  hash.c
  KeccakHash.c
  KeccakP-1600-reference.c
  KeccakSponge.c
  owf_proof.c
  polynomials.c
  polynomials_impl.c
  prgs.c
  quicksilver.c
  randomness_randombytes.c
  small_vole.c
  transpose.c
  universal_hash.c
  util.c
  vector_com.c
  vole_check.c
  vole_commit.c
)

objects=()
for name in "${sources[@]}"; do
  obj="$build/${name%.c}.o"
  gcc -O2 -march=x86-64 -std=c11 -Wpedantic -Wall -Wextra \
    -Wno-missing-braces -I"$src" -c "$src/$name" -o "$obj" \
    2>> "$out/compile.stderr"
  objects+=("$obj")
done

gcc -O2 -march=x86-64 -std=c11 -Wpedantic -Wall -Wextra \
  -I"$src" -o "$build/drng_default_interface_harness" \
  "$out/drng_default_interface_harness.c" "${objects[@]}" -lcrypto \
  2>> "$out/compile.stderr"

"$build/drng_default_interface_harness" > "$out/run1.stdout" 2> "$out/run1.stderr"
"$build/drng_default_interface_harness" > "$out/run2.stdout" 2> "$out/run2.stderr"
"$build/drng_default_interface_harness" seeded-A > "$out/seeded-A.stdout" 2> "$out/seeded-A.stderr"
"$build/drng_default_interface_harness" seeded-B > "$out/seeded-B.stdout" 2> "$out/seeded-B.stderr"

cmp "$out/run1.stdout" "$out/run2.stdout"
if cmp -s "$out/seeded-A.stdout" "$out/seeded-B.stdout"; then
  echo "unexpectedly identical seeded controls" >&2
  exit 1
fi

cp "$build/drng_default_interface_harness" "$out/drng_default_interface_harness"

{
  uname -a
  gcc --version | head -n 1
  sha256sum \
    "$src/SIG_AlgorithmInstance.h" \
    "$src/SIG_AlgorithmInstance.c" \
    "$src/randomness_randombytes.c" \
    "$src/api.c" \
    "$src/KAT_SIG.c"
} > "$out/environment-and-source-hashes.txt"

sha256sum "$out"/*.stdout \
  "$out"/*.stderr \
  "$out/drng_default_interface_harness.c" \
  "$out/drng_default_interface_harness" \
  "$out/compile.stderr" \
  "$out/environment-and-source-hashes.txt" \
  > "$out/evidence-manifest.sha256"

printf 'unseeded outputs identical; seeded controls differ\n'
printf 'stdout SHA256: '
sha256sum "$out/run1.stdout" | awk '{print $1}'
