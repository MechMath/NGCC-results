#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

COMMON_CPPFLAGS='-Ibike_kem_ml/include -Ibike_kem_ml/include/internal -Ibike_kem_ml/src/third_party_src -Ibike_kem_ml/tests/FromNIST -Ibike_kem_ml/kat -DX86_64 -DSECURITY_BITS=512 -DUSE_NIST_RAND -DBIKE_MLTHRE_ENABLED=1 -DBIKE_MLTHRE_DELTA_ENABLED=1 -DBIKE_MLTHRE_SAMPLING=0 -DBIKE_L7_DYNAMIC_THRESHOLD=1 -DBIKE_L7_EMPIRICAL_THRESHOLD=0 -DUSE_API_PKC_AUX=1 -DSTANDALONE_IMPL=1 -DVERBOSE=1'
COMMON_LINK_FLAGS='-O3 -ggdb -fPIC -std=c99 -Wall -Wextra -Wno-unused-parameter -Ibike_kem_ml/include -Ibike_kem_ml/include/internal -Ibike_kem_ml/src/third_party_src -Ibike_kem_ml/tests/FromNIST -Ibike_kem_ml/kat -DX86_64 -DSECURITY_BITS=512 -DUSE_NIST_RAND -DBIKE_MLTHRE_ENABLED=1 -DBIKE_MLTHRE_DELTA_ENABLED=1 -DBIKE_MLTHRE_SAMPLING=0 -DBIKE_L7_DYNAMIC_THRESHOLD=1 -DBIKE_L7_EMPIRICAL_THRESHOLD=0 -DUSE_API_PKC_AUX=1 -DSTANDALONE_IMPL=1'

make clean SECURITY=512 BUILD_DIR=build_ref >/dev/null 2>&1 || true
make clean SECURITY=512 BUILD_DIR=build_opt >/dev/null 2>&1 || true
make -j8 SECURITY=512 BUILD_DIR=build_ref \
  CPPFLAGS="${COMMON_CPPFLAGS} -DBIKE_L7_REFERENCE_DECODER=1" \
  > build_ref.log 2>&1
make -j8 SECURITY=512 BUILD_DIR=build_opt \
  CPPFLAGS="${COMMON_CPPFLAGS} -DBIKE_L7_REFERENCE_DECODER=0" \
  > build_opt.log 2>&1

gcc ${COMMON_LINK_FLAGS} -DBIKE_L7_REFERENCE_DECODER=1 \
  policy_probe.c bike_kem_ml/tests/FromNIST/rng.c \
  build_ref/libbike_kem_ml.a -lcrypto -lm -o build_ref/policy_probe
gcc ${COMMON_LINK_FLAGS} -DBIKE_L7_REFERENCE_DECODER=0 \
  policy_probe.c bike_kem_ml/tests/FromNIST/rng.c \
  build_opt/libbike_kem_ml.a -lcrypto -lm -o build_opt/policy_probe

mkdir -p corpus outputs/ref outputs/opt
for i in 0 1 2 3; do
  build_opt/policy_probe gen corpus "$i" > "corpus/case_$(printf '%02d' "$i").gen.log"
done

printf 'build\tcase\tvariant\trepeat\trc\twall_s\tlog\terr\tss\n' > run_meta.tsv
for build in ref opt; do
  exe="build_${build}/policy_probe"
  for i in 00 01 02 03; do
    for variant in valid c1_bit0 c0_bit0 c0_last c0_mask32; do
      for repeat in 1 2; do
        if [[ "$variant" != valid && "$repeat" = 2 ]]; then
          continue
        fi
        stem="outputs/${build}/case_${i}_${variant}.repeat${repeat}"
        start=$(date +%s%N)
        set +e
        timeout 60 "$exe" dec "corpus/case_${i}.sk" \
          "corpus/case_${i}_${variant}.ct" "${stem}.ss" \
          > "${stem}.log" 2> "${stem}.err"
        rc=$?
        set -e
        end=$(date +%s%N)
        wall=$(awk -v s="$start" -v e="$end" \
          'BEGIN {printf "%.6f", (e-s)/1e9}')
        printf '%s\tcase_%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
          "$build" "$i" "$variant" "$repeat" "$rc" "$wall" \
          "${stem}.log" "${stem}.err" "${stem}.ss" >> run_meta.tsv
      done
    done
  done
done

python3 analyze_policy.py
