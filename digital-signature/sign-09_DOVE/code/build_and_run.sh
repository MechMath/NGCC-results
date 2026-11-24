#!/usr/bin/env bash
set -euo pipefail

root=/home/mmat/mmat-preview/runs/ngcc-sign-09-ds01/run/slots/b977949983924d87/refsrc/Digital_Signature-DOVE-x86-reference_implementation
work=/home/mmat/mmat-preview/runs/ngcc-sign-09-ds01/run/slots/67c5eb5e760a43c9
impltree="$root/API_PKC/Implementations"
harness="$work/dove_envelope_harness.c"
artifact_root="$work/envelope_artifacts"
mkdir -p "$artifact_root/bin" "$artifact_root/logs"

ref_sources=(gf256.c matrix.c uov/blas_matrix_ref.c auxfunc.c drng.c SIG_AlgorithmInstance.c)
opt_sources=(gf256.c matrix.c uov/blas_matrix_avx2.c uov/blas_matrix_ref.c uov/gf16_tabs.c uov/gf256_tabs.c auxfunc.c drng.c SIG_AlgorithmInstance.c)

for impl in Reference_Implementation Optimized_Implementation; do
  if [[ "$impl" == Reference_Implementation ]]; then
    variants=(DOVE_classic_ref DOVE_pkc_skc_ref)
    sources=("${ref_sources[@]}")
    extra=()
  else
    variants=(DOVE_classic_avx2 DOVE_pkc_skc_avx2)
    sources=("${opt_sources[@]}")
    extra=(-mavx2)
  fi
  for variant in "${variants[@]}"; do
    for profile in 128 256 512; do
      tag="${variant}_${profile}"
      dir="$impltree/$impl/$variant"
      bin="$artifact_root/bin/$tag"
      cmd=(gcc -std=c99 -O2 -Wall -Wextra -Wno-unused-parameter
           -DDOVE_PARAM_SET=DOVE${profile} "${extra[@]}"
           -I"$dir" -I"$dir/uov" -o "$bin"
           "${sources[@]/#/$dir/}" "$harness")
      printf '%q ' "${cmd[@]}" > "$artifact_root/logs/${tag}.compile.cmd"
      printf '\n' >> "$artifact_root/logs/${tag}.compile.cmd"
      "${cmd[@]}" > "$artifact_root/logs/${tag}.compile.stdout" 2> "$artifact_root/logs/${tag}.compile.stderr"
      timeout 600 "$bin" "$variant" "DOVE_${profile}" \
        > "$artifact_root/logs/${tag}.run.stdout" \
        2> "$artifact_root/logs/${tag}.run.stderr"
      printf '%s\n' "$?" > "$artifact_root/logs/${tag}.run.exit"
    done
  done
done
