#!/usr/bin/env bash
set -u
root=/home/mmat/mmat-preview/runs/ngcc-sign-09-ds01/run/slots/b977949983924d87/refsrc/Digital_Signature-DOVE-x86-reference_implementation
work=/home/mmat/mmat-preview/runs/ngcc-sign-09-ds01/run/slots/67c5eb5e760a43c9
impltree="$root/API_PKC/Implementations/Optimized_Implementation"
harness="$work/dove_envelope_harness.c"
art="$work/envelope_artifacts"
mkdir -p "$art/bin" "$art/logs"
sources=(gf256.c matrix.c uov/blas_matrix_avx2.c uov/blas_matrix_ref.c uov/gf16_tabs.c uov/gf256_tabs.c auxfunc.c drng.c SIG_AlgorithmInstance.c)
for variant in DOVE_classic_avx2 DOVE_pkc_skc_avx2; do
  for profile in 128 256 512; do
    tag="${variant}_${profile}"
    dir="$impltree/$variant"
    bin="$art/bin/$tag"
    gcc -std=c99 -O2 -Wall -Wextra -Wno-unused-parameter \
      -DDOVE_PARAM_SET=DOVE${profile} -mavx2 -I"$dir" -I"$dir/uov" \
      -o "$bin" "${sources[@]/#/$dir/}" "$harness" \
      >"$art/logs/${tag}.compile.stdout" 2>"$art/logs/${tag}.compile.stderr"
    cc_ret=$?
    printf '%s\n' "$cc_ret" >"$art/logs/${tag}.compile.exit"
    if [[ "$cc_ret" -eq 0 ]]; then
      timeout 600 "$bin" "$variant" "DOVE_${profile}" \
        >"$art/logs/${tag}.run.stdout" 2>"$art/logs/${tag}.run.stderr"
      printf '%s\n' "$?" >"$art/logs/${tag}.run.exit"
    fi
  done
done
