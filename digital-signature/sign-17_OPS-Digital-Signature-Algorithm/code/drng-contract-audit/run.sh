#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
SRC="$ROOT/ops128-ref"
CORE="sign.c mult.c packing.c polyvec.c poly.c ntt.c reduce.c rounding.c auxfunc.c drng.c"
CORE_OBJS=""

cd "$ROOT"
rm -rf build
mkdir build

cc -std=c99 -O2 -Wall -Wextra -I"$SRC" -c public_consumer.c -o build/public_consumer.o
for f in $CORE; do
    cc -std=c99 -O2 -Wall -Wextra -I"$SRC" -c "$SRC/$f" -o "build/${f%.c}.o"
    CORE_OBJS="$CORE_OBJS build/${f%.c}.o"
done
cc -std=c99 -O2 -Wall -Wextra -I"$SRC" -c "$SRC/SIG_AlgorithmInstance.c" -o build/SIG_AlgorithmInstance.o

if cc build/public_consumer.o build/SIG_AlgorithmInstance.o $CORE_OBJS \
      -o build/public-consumer 2>public-link-failure.txt; then
    echo "UNEXPECTED: public-only consumer linked"
    exit 1
fi

cc -std=c99 -O2 -Wall -Wextra -I"$SRC" zero_init_consumer.c \
   build/SIG_AlgorithmInstance.o $CORE_OBJS -o build/zero-init-consumer

rm -rf run1 run2 initialized-control
mkdir run1 run2
(cd run1 && ../build/zero-init-consumer > transcript.txt)
(cd run2 && ../build/zero-init-consumer > transcript.txt)
cc -std=c99 -O2 -Wall -Wextra -DCONTROL_INIT -I"$SRC" zero_init_consumer.c \
   build/SIG_AlgorithmInstance.o $CORE_OBJS -o build/initialized-control
mkdir initialized-control
(cd initialized-control && ../build/initialized-control > transcript.txt)
sha256sum run1/pk.bin run2/pk.bin run1/sk.bin run2/sk.bin run1/sn.bin run2/sn.bin
cmp run1/pk.bin run2/pk.bin
cmp run1/sk.bin run2/sk.bin
cmp run1/sn.bin run2/sn.bin
cat run1/transcript.txt
sha256sum initialized-control/pk.bin initialized-control/sk.bin initialized-control/sn.bin
if cmp -s run1/pk.bin initialized-control/pk.bin; then
    echo "UNEXPECTED: explicit initialization did not change pk"
    exit 1
fi
printf 'explicit initialization changed pk/sk/sn; see hashes above\n'
