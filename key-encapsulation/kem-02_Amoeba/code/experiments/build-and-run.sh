#!/bin/sh
set -eu
root=submission/Implementations/Reference_Implementation/Amoeba-576/src
gcc -O2 -std=gnu11 -fgnu89-inline -DSECURITY_LEVEL=128 \
  -I"$root/symmetric" -I"$root/backend" \
  experiments/repro_1046.c "$root"/symmetric/*.c "$root"/backend/*.c \
  -o experiments/bin/repro_1046
./experiments/bin/repro_1046 | tee experiments/repro_1046.output.txt

gcc -O2 -std=gnu11 -fgnu89-inline -DSECURITY_LEVEL=128 \
  -I"$root/symmetric" -I"$root/backend" \
  experiments/attack_1046.c "$root"/symmetric/*.c "$root"/backend/*.c \
  -o experiments/bin/attack_1046
./experiments/bin/attack_1046 | tee experiments/attack_1046.output.jsonl
