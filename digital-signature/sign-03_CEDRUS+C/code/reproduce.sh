#!/usr/bin/env bash
set -euo pipefail

ZIP=cedrus+c.zip
EXPECTED=a31de849cf0a0703a4e57decbdf4d97b100d00dc74756feaded2c04a7593e110
SRC=src-repro/Implementations/Optimized_Implementation/CEDRUSC-160f

test "$(sha256sum "$ZIP" | awk '{print $1}')" = "$EXPECTED"
if test -e src-repro; then
    echo "src-repro already exists; use a fresh working directory" >&2
    exit 2
fi
mkdir src-repro
python3 -m zipfile -e "$ZIP" src-repro

COMMON=(
    "$SRC/sign.c" "$SRC/address.c" "$SRC/auxfunc.c" "$SRC/counters.c"
    "$SRC/drng.c" "$SRC/hash_sm3.c" "$SRC/hash_sm3x8.c" "$SRC/merkle.c"
    "$SRC/fors.c" "$SRC/sm3x8.c" "$SRC/thash_sm3_simple.c"
    "$SRC/thash_sm3_simplex8.c" "$SRC/utils.c" "$SRC/utils_avx2.c"
    "$SRC/utilsx1.c" "$SRC/wots.c" "$SRC/wotsx1.c"
)

gcc -O3 -march=native -mavx2 -fomit-frame-pointer -funroll-loops \
    -Wall -Wextra -flto -DSPX_ENABLE_X8_WOTS -DPARAMS=cedrusc-sm3-160f \
    -I"$SRC" -I"$SRC/params" \
    -o optimized_attack-repro optimized_attack.c "${COMMON[@]}"

gcc -O3 -march=native -mavx2 -fomit-frame-pointer -funroll-loops \
    -Wall -Wextra -flto -DSPX_ENABLE_X8_WOTS -DPARAMS=cedrusc-sm3-160f \
    -I"$SRC" -I"$SRC/params" \
    -o optimized_verify-repro optimized_verify.c "${COMMON[@]}"

TIMEFORMAT='elapsed=%3R user=%3U sys=%3S'
time ./optimized_attack-repro

./optimized_verify-repro valid optimized-forged-signature.bin
if ./optimized_verify-repro signature-mutation optimized-forged-signature.bin; then
    echo "signature mutation unexpectedly accepted" >&2
    exit 3
fi
if ./optimized_verify-repro message-mutation optimized-forged-signature.bin; then
    echo "message mutation unexpectedly accepted" >&2
    exit 3
fi
