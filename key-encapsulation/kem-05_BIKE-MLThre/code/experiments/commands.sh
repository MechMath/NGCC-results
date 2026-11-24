#!/bin/sh
set -eu

# From the task workspace root. Rebuild the optimized 128-bit profile.
make -C extracted/Implementations/optimization clean SECURITY=128
make -C extracted/Implementations/optimization -j2 all SECURITY=128

gcc -O2 -std=c99 -Wall -Wextra -Wno-unused-parameter \
  -DX86_64 -DSECURITY_BITS=128 -DUSE_NIST_RAND \
  -DBIKE_MLTHRE_ENABLED=1 -DBIKE_MLTHRE_DELTA_ENABLED=1 \
  -DBIKE_MLTHRE_SAMPLING=0 -DBIKE_L7_REFERENCE_DECODER=1 \
  -DBIKE_L7_DYNAMIC_THRESHOLD=1 -DBIKE_L7_EMPIRICAL_THRESHOLD=0 \
  -DUSE_API_PKC_AUX=1 -DSTANDALONE_IMPL=1 \
  -Iextracted/Implementations/optimization/bike_kem_ml/include \
  -Iextracted/Implementations/optimization/bike_kem_ml/include/internal \
  -Iextracted/Implementations/optimization/bike_kem_ml/src/third_party_src \
  -Iextracted/Implementations/optimization/bike_kem_ml/tests/FromNIST \
  experiments/cross_profile_dec.c \
  extracted/Implementations/optimization/bike_kem_ml/tests/FromNIST/rng.c \
  extracted/Implementations/optimization/build_kat_128/libbike_kem_ml.a \
  -lcrypto -lm -o experiments/cross_profile_dec

./experiments/cross_profile_dec \
  extracted/Test_Vectors/TEST_VECTORS/reference/KAT_KEM_BIKE_MLThre_128.txt

# Reference timing control.
make -C extracted/Implementations/reference clean SECURITY=128
make -C extracted/Implementations/reference -j2 SECURITY=128
gcc -O3 -std=c99 -Wall -Wextra -Wno-unused-parameter \
  -DNIST_RAND=1 -DBIKE_SECURITY_128 -DBIKE_MLTHRE_ENABLED=1 \
  -Iextracted/Implementations/reference experiments/ref_dec_timing.c \
  extracted/Implementations/reference/.build/128/libbike_v2.a \
  -lcrypto -lm -o experiments/ref_dec_timing
./experiments/ref_dec_timing \
  extracted/Test_Vectors/TEST_VECTORS/reference/KAT_KEM_BIKE_MLThre_128.txt 300
