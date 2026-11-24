#!/usr/bin/env bash
set -euo pipefail

slot_dir=$(cd "$(dirname "$0")/.." && pwd)
root="$slot_dir/original/Implementations/Reference_Implementation/GreatWall128s"
out="$slot_dir/experiments/results"
mkdir -p "$out"

test "$(sha256sum "$slot_dir/GreatWall.zip" | cut -d' ' -f1)" = \
  814cd3b977ddc0cc59828861c145580473b1a62a66da852b078edbaf689f5a8d

# Positive control, using the unchanged original Makefile.
make -C "$root" -j2
(
  cd "$root"
  ./KAT_SIG
  cmp output/KAT_SIG_GreatWall128s.txt \
      ../../../Test_Vectors/KAT_SIG_GreatWall128s.txt
)

# Exact api.c + exact SIG_AlgorithmInstance.c, with clearly labelled stubs.
cc -O2 -std=c11 -Wall -Wextra -Wpedantic -I "$root" \
  "$slot_dir/experiments/callflow_harness.c" \
  "$root/api.c" "$root/SIG_AlgorithmInstance.c" \
  -o "$slot_dir/experiments/callflow_harness"
"$slot_dir/experiments/callflow_harness" \
  > "$out/callflow.stdout" 2> "$out/callflow.stderr"

# Exact implementation with ASan/UBSan. The long source list is intentional:
# all build inputs are the original GreatWall128s tree.
sources=(
  drng.c api.c aes.c aes_impl.c block.c block_impl.c faest.c greatwall.c
  greatwall-128-matrix.c greatwall_impl.c hash.c KeccakHash.c
  KeccakP-1600-reference.c KeccakSponge.c owf_proof.c polynomials.c
  polynomials_impl.c prgs.c quicksilver.c randomness_randombytes.c small_vole.c
  transpose.c universal_hash.c util.c vector_com.c vole_check.c vole_commit.c
)
source_paths=()
for name in "${sources[@]}"; do source_paths+=("$root/$name"); done

cc -O1 -g -std=c11 -fno-omit-frame-pointer -fsanitize=address,undefined \
  -I "$root" "$slot_dir/experiments/short_asan_harness.c" \
  "${source_paths[@]}" -o "$slot_dir/experiments/short_asan_harness" \
  > "$out/asan_compile.stdout" 2> "$out/asan_compile.stderr"

ASAN_OPTIONS=abort_on_error=1:symbolize=1
UBSAN_OPTIONS=print_stacktrace=1
export ASAN_OPTIONS="$ASA_OPTIONS"
export UBSAN_OPTIONS="$UBSAN_OPTIONS"

"$slot_dir/experiments/short_asan_harness" valid \
  > "$out/asan_valid.stdout" 2> "$out/asan_valid.stderr"

for n in 2757 1 0; do
  set +e
  "$slot_dir/experiments/short_asan_harness" "$n" \
    > "$out/asan_short_${n}.stdout" 2> "$out/asan_short_${n}.stderr"
  rc=$?
  set -e
  test "$rc" -eq 134
done
