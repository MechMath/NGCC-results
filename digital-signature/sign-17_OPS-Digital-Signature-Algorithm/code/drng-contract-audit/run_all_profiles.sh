#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REF_CORE="sign.c mult.c packing.c polyvec.c poly.c ntt.c reduce.c rounding.c auxfunc.c drng.c"
AVX_CORE="sign.c packing.c polyvec.c poly.c rejsample.c ntt.c pointwise.S consts.c reduce.c rounding.c sm3x4.c auxfunc.c drng.c"

cd "$ROOT"
rm -rf all-prof-logs
mkdir all-prof-logs

for SRC in source/OPSsig-128 source/OPSsig-256 source/OPSsig-512 \
           source/OPSsig-128-avx2 source/OPSsig-256-avx2 source/OPSsig-512-avx2; do
    NAME=$(basename "$SRC")
    OUT="all-prof-logs/$NAME"
    mkdir -p "$OUT/build"
    case "$NAME" in
        *-avx2) CORE="$AVX_CORE" ;;
        *) CORE="$REF_CORE" ;;
    esac

    cc -std=c99 -O2 -Wall -Wextra -mavx2 -I"$SRC" \
       -c public_consumer.c -o "$OUT/build/public_consumer.o"
    cc -std=c99 -O2 -Wall -Wextra -mavx2 -I"$SRC" \
       -c zero_init_consumer.c -o "$OUT/build/zero_init_consumer.o"
    OBJS=""
    for f in $CORE; do
        obj="$OUT/build/${f%.*}.o"
        cc -std=c99 -O2 -Wall -Wextra -mavx2 -I"$SRC" -c "$SRC/$f" -o "$obj"
        OBJS="$OBJS $obj"
    done
    cc -std=c99 -O2 -Wall -Wextra -mavx2 -I"$SRC" \
       -c "$SRC/SIG_AlgorithmInstance.c" -o "$OUT/build/SIG_AlgorithmInstance.o"

    if cc "$OUT/build/public_consumer.o" \
          "$OUT/build/SIG_AlgorithmInstance.o" $OBJS \
          -o "$OUT/public-consumer" 2>"$OUT/public-link-failure.txt"; then
        echo "$NAME UNEXPECTED_PUBLIC_LINK_SUCCESS"
        exit 1
    fi
    grep -q 'undefined reference to `drng_algorithm' "$OUT/public-link-failure.txt"
    cc "$OUT/build/zero_init_consumer.o" \
       "$OUT/build/SIG_AlgorithmInstance.o" $OBJS \
       -o "$OUT/zero-init-consumer"
    mkdir "$OUT/run1" "$OUT/run2"
    (cd "$OUT/run1" && ../zero-init-consumer > transcript.txt)
    (cd "$OUT/run2" && ../zero-init-consumer > transcript.txt)
    cmp "$OUT/run1/pk.bin" "$OUT/run2/pk.bin"
    cmp "$OUT/run1/sk.bin" "$OUT/run2/sk.bin"
    cmp "$OUT/run1/sn.bin" "$OUT/run2/sn.bin"
    printf '%s ' "$NAME"
    cat "$OUT/run1/transcript.txt"
    sha256sum "$OUT/run1/pk.bin" "$OUT/run1/sk.bin" "$OUT/run1/sn.bin"
done
