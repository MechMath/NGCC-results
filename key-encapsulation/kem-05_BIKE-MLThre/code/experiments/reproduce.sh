#!/usr/bin/env bash
set -euo pipefail

slot="$(cd "$(dirname "$0")/.." && pwd)"
original_root="${ORIGINAL_ROOT:-/home/mmat/mmat-preview/runs/ngcc-kem-05-ds01/insights/73c39a153a930631/authors/687eb1ad2e4b4d0c/native/original/extracted}"
exp="$slot/experiments"

rm -rf "$exp/reference128" "$exp/reference128_off" \
       "$exp/reference256" "$exp/reference256_off" \
       "$exp/optimization128" "$exp/optimization128_off" \
       "$exp/optimization128_l1json"
cp -a "$original_root/Implementations/reference" "$exp/reference128"
cp -a "$original_root/Implementations/reference" "$exp/reference128_off"
cp -a "$original_root/Implementations/reference" "$exp/reference256"
cp -a "$original_root/Implementations/reference" "$exp/reference256_off"
cp -a "$original_root/Implementations/optimization" "$exp/optimization128"
cp -a "$original_root/Implementations/optimization" "$exp/optimization128_off"
cp -a "$original_root/Implementations/optimization" "$exp/optimization128_l1json"

sed -i 's/BIKE_MLTHRE_ENABLED=1/BIKE_MLTHRE_ENABLED=0/g' \
  "$exp/reference128_off/Makefile" "$exp/reference256_off/Makefile"
sed -i 's/BIKE_MLTHRE_ENABLED=1/BIKE_MLTHRE_ENABLED=0/g; s/BIKE_MLTHRE_DELTA_ENABLED=1/BIKE_MLTHRE_DELTA_ENABLED=0/g' \
  "$exp/optimization128_off/Makefile"

python3 "$original_root/Implementations/optimization/model/export_mlp_to_fixed_c.py" \
  --model "$original_root/Implementations/optimization/model/aws_l1_mlthre_mlp_1000.json" \
  --out-dir "$exp/optimization128_l1json/bike_kem_ml/src/decode"

make -C "$exp/reference128" clean
make -C "$exp/reference128" SECURITY=128 -j8
make -C "$exp/reference128_off" clean
make -C "$exp/reference128_off" SECURITY=128 -j8
make -C "$exp/optimization128" clean
make -C "$exp/optimization128" SECURITY=128 -j8
make -C "$exp/optimization128_off" clean
make -C "$exp/optimization128_off" SECURITY=128 -j8
make -C "$exp/optimization128_l1json" clean
make -C "$exp/optimization128_l1json" SECURITY=128 -j8

gcc -O2 -std=gnu11 -DVARIANT='"ref_on"' -I"$exp/reference128" \
  -I"$exp/reference128/FromNIST" "$exp/timing_harness.c" \
  "$exp/reference128/.build/128/libbike_v2.a" -lcrypto -lm \
  -o "$exp/reference128/timing_ref_on"
gcc -O2 -std=gnu11 -DVARIANT='"ref_off"' -I"$exp/reference128" \
  -I"$exp/reference128/FromNIST" "$exp/timing_harness.c" \
  "$exp/reference128_off/.build/128/libbike_v2.a" -lcrypto -lm \
  -o "$exp/reference128/timing_ref_off"

opt_i="$exp/optimization128/bike_kem_ml"
gcc -O2 -std=gnu11 -DVARIANT='"opt_on"' -DSECURITY_BITS=128 -DX86_64 \
  -I"$opt_i/include" -I"$opt_i/include/internal" -I"$opt_i/tests" \
  -I"$opt_i/tests/FromNIST" "$exp/timing_harness.c" \
  "$opt_i/tests/FromNIST/rng.c" \
  "$exp/optimization128/build_kat_128/libbike_kem_ml.a" -lcrypto -lm \
  -o "$exp/optimization128/timing_opt_on"

opt_off_i="$exp/optimization128_off/bike_kem_ml"
gcc -O2 -std=gnu11 -DVARIANT='"opt_off"' -DSECURITY_BITS=128 -DX86_64 \
  -I"$opt_off_i/include" -I"$opt_off_i/include/internal" -I"$opt_off_i/tests" \
  -I"$opt_off_i/tests/FromNIST" "$exp/timing_harness.c" \
  "$opt_off_i/tests/FromNIST/rng.c" \
  "$exp/optimization128_off/build_kat_128/libbike_kem_ml.a" -lcrypto -lm \
  -o "$exp/optimization128_off/timing_opt_off"

taskset -c 2 "$exp/reference128/timing_ref_on" 2 > "$exp/logs/ref_on128.csv"
taskset -c 4 "$exp/reference128/timing_ref_off" 4 > "$exp/logs/ref_off128.csv"
taskset -c 6 "$exp/optimization128/timing_opt_on" 6 > "$exp/logs/opt_on128.csv"
taskset -c 8 "$exp/optimization128_off/timing_opt_off" 8 > "$exp/logs/opt_off128.csv"
python3 "$exp/analyze_timing.py"
