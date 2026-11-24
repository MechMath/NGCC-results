#!/usr/bin/env bash
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
src="$here/evidence/original-reference-128s"
out="$here/evidence/implementation-robustness/reproduced"
mkdir -p "$out"

expected_zip_sha256="814cd3b977ddc0cc59828861c145580473b1a62a66da852b078edbaf689f5a8d"
expected_kat_sha256="03b60bfcae5bac1d7dbdf06c805f42a3b17890840619e55b6575c39915aaecbd"
expected_api_sha256="1dc6dcf46227d0e6db7a5e5f3f066314ac53c60e373059162f00ce4cbe1c526b"
expected_wrapper_sha256="27129256ac1fe167a682278079ae303737f0a5f5b02d74b09b38f41ea4fb78dd"

test "$(sha256sum "$src/api.c" | cut -d' ' -f1)" = "$expected_api_sha256"
test "$(sha256sum "$src/SIG_AlgorithmInstance.c" | cut -d' ' -f1)" = "$expected_wrapper_sha256"
test "$(sha256sum "$here/evidence/original-reference-128s/output/KAT_SIG_GreatWall128s.txt" | cut -d' ' -f1)" = "$expected_kat_sha256"

# Positive control: build and run the unmodified submitted known-answer test.
(
  cd "$src"
  make clean
  make
  ./KAT_SIG
)
cmp "$src/output/KAT_SIG_GreatWall128s.txt" \
    "$here/evidence/original-reference-128s/output/KAT_SIG_GreatWall128s.txt"

# Exact-source call-flow control. Only rand_bytes, faest_pubkey, faest_sign,
# and faest_verify are replaced by the explicitly labelled stubs in the
# harness; api.c and SIG_AlgorithmInstance.c are the original files.
gcc -O1 -g -I"$src" \
  "$here/evidence/implementation-robustness/callflow_harness.c" \
  "$src/api.c" \
  "$src/SIG_AlgorithmInstance.c" \
  -o "$out/callflow_harness.rebuilt"
"$out/callflow_harness.rebuilt" >"$out/callflow.stdout" 2>"$out/callflow.stderr"
cmp "$out/callflow.stdout" \
    "$here/evidence/implementation-robustness/results/callflow.stdout"

# The exact implementation plus the sanitizer harness. SIG_AlgorithmInstance.c
# is not needed for the direct raw-API call.
original_sources=(
  api.c aes.c aes_impl.c block.c block_impl.c faest.c greatwall.c
  greatwall-128-matrix.c greatwall_impl.c hash.c KeccakHash.c
  KeccakP-1600-reference.c KeccakSponge.c owf_proof.c polynomials.c
  polynomials_impl.c prgs.c quicksilver.c randomness_randombytes.c
  small_vole.c transpose.c universal_hash.c util.c vector_com.c
  vole_check.c vole_commit.c drng.c
)
source_paths=()
for name in "${original_sources[@]}"; do
  source_paths+=("$src/$name")
done

gcc -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer \
  -I"$src" \
  "${source_paths[@]}" \
  "$here/evidence/implementation-robustness/short_asan_harness.c" \
  -lcrypto \
  -o "$out/short_asan_harness.rebuilt"

ASAN_OPTIONS=abort_on_error=1:halt_on_error=1 \
  "$out/short_asan_harness.rebuilt" valid \
  >"$out/asan_valid.stdout" 2>"$out/asan_valid.stderr"

for short_length in 0 1 2757; do
  set +e
  ASAN_OPTIONS=abort_on_error=1:halt_on_error=1 \
    "$out/short_asan_harness.rebuilt" "$short_length" \
    >"$out/asan_short_${short_length}.stdout" \
    2>"$out/asan_short_${short_length}.stderr"
  status=$?
  set -e
  test "$status" -eq 134
  grep -q "ERROR: AddressSanitizer: stack-buffer-overflow" \
    "$out/asan_short_${short_length}.stderr"
  grep -q "crypto_sign_open" "$out/asan_short_${short_length}.stderr"
  grep -q "faest_verify" "$out/asan_short_${short_length}.stderr"
done

# End-to-end control on the designated SIG_AlgorithmInstance interface. The
# honest key signs and verifies. A nonempty but invalid secret key of the
# accepted 36-byte length makes the underlying signer fail, yet sig_sign
# returns success and a signature that the honest public key rejects.
wrapper_sources=("${source_paths[@]}" "$src/SIG_AlgorithmInstance.c")
gcc -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer \
  -I"$src" \
  "${wrapper_sources[@]}" \
  "$here/evidence/implementation-robustness/wrong_key_harness.c" \
  -lcrypto \
  -o "$out/wrong_key_harness.rebuilt" \
  2>"$out/wrong_key_compile.stderr"
ASAN_OPTIONS=detect_leaks=0:abort_on_error=1:halt_on_error=1 \
  "$out/wrong_key_harness.rebuilt" \
  >"$out/wrong_key.stdout" 2>"$out/wrong_key.stderr"
grep -q "honest_sign ret=0 sn_len=2758" "$out/wrong_key.stdout"
grep -q "honest_verify ret=0" "$out/wrong_key.stdout"
grep -q "zero_key_sign_ret=0 sn_len=2758" "$out/wrong_key.stdout"
grep -q "zero_key_signature_verify_ret=-1" "$out/wrong_key.stdout"

sha256sum "$src/api.c" "$src/SIG_AlgorithmInstance.c" \
  "$here/evidence/original-reference-128s/output/KAT_SIG_GreatWall128s.txt" \
  "$out/callflow_harness.rebuilt" \
  "$out/short_asan_harness.rebuilt" \
  "$out/wrong_key_harness.rebuilt" \
  >"$out/result-sha256.txt"

printf 'reproduction passed; expected ZIP sha256 %s\n' "$expected_zip_sha256"

# Independent source-identity audit of all 16 implementation/profile copies.
(
  cd "$here/evidence/profile-source-identity"
  python3 audit_source_identity.py > source_identity_audit.stdout.txt
)
grep -q "all 16 api.c and SIG_AlgorithmInstance.c copies match" \
  "$here/evidence/profile-source-identity/source_identity_audit.stdout.txt"
