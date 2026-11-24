#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "$0")" && pwd)"
src="$root/original/Implementations/Reference_Implementation/GreatWall128s"
out="$root/interface-results"
mkdir -p "$out"

expected_zip=814cd3b977ddc0cc59828861c145580473b1a62a66da852b078edbaf689f5a8d
zip_path="$root/original/GreatWall.zip"

if [[ -f "$zip_path" ]]; then
  actual_zip="$(sha256sum "$zip_path" | cut -d' ' -f1)"
  [[ "$actual_zip" == "$expected_zip" ]]
else
  printf 'note: shared ZIP not found; extracted source hashes are checked below\n'
fi

sources=(
  SIG_AlgorithmInstance.c drng.c api.c aes.c aes_impl.c block.c
  block_impl.c faest.c greatwall.c greatwall-128-matrix.c greatwall_impl.c
  hash.c KeccakHash.c KeccakP-1600-reference.c KeccakSponge.c owf_proof.c
  polynomials.c polynomials_impl.c prgs.c quicksilver.c randomness_randombytes.c
  small_vole.c transpose.c universal_hash.c util.c vector_com.c vole_check.c
  vole_commit.c
)

objects=()
for file in "${sources[@]}"; do
  obj="$out/${file%.c}.o"
  gcc -O2 -std=c11 -Wpedantic -Wall -Wextra -Wno-missing-braces \
    -I"$src" -c "$src/$file" -o "$obj"
  objects+=("$obj")
done

gcc -O2 -std=c11 -Wpedantic -Wall -Wextra -Wno-missing-braces \
  -I"$src" -c "$root/interface_trace.c" -o "$out/interface_trace.o"
gcc -O2 -o "$out/interface_trace" "$out/interface_trace.o" \
  "${objects[@]}" -lcrypto

cd "$out"
./interface_trace zero zero-a | tee zero-a.stdout.txt
./interface_trace zero zero-b | tee zero-b.stdout.txt
cmp zero-a.pk zero-b.pk
cmp zero-a.sk zero-b.sk
cmp zero-a.sig1 zero-b.sig1
printf 'independent_zero_process_keypair_and_signature_equal=1\n' | tee zero-files.stdout.txt

./interface_trace consecutive consecutive | tee consecutive.stdout.txt
./interface_trace reset reset | tee reset.stdout.txt

sha256sum "$src"/{api.c,SIG_AlgorithmInstance.c,faest.c,drng.c,randomness_randombytes.c,randomness_os.c,vector_com.c} \
  > source-hashes.txt
sha256sum *.pk *.sk *.sig1 *.sig2 > generated-hashes.txt
