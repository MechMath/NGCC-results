#!/usr/bin/env bash
set -euo pipefail
root="originals/extracted/Implementations/Reference_Implementation/CEDRUSC-256f"
mkdir -p experiments
gcc -O3 -fomit-frame-pointer -funroll-loops -Wall -Wextra -flto \
  -DPARAMS=cedrusc-sm3-256f -I"$root" -I"$root/params" \
  -c attack256f.c -o attack256f.o
gcc -O3 -fomit-frame-pointer -funroll-loops -flto -o experiments/attack256f \
  attack256f.o \
  "$root/sign.o" "$root/address.o" "$root/auxfunc.o" "$root/counters.o" \
  "$root/drng.o" "$root/hash_sm3.o" "$root/merkle.o" "$root/fors.o" \
  "$root/randombytes.o" "$root/thash_sm3_simple.o" "$root/utils.o" \
  "$root/utilsx1.o" "$root/wots.o" "$root/wotsx1.o"
gcc -O3 -fomit-frame-pointer -funroll-loops -Wall -Wextra -flto \
  -DPARAMS=cedrusc-sm3-256f -I"$root" -I"$root/params" -c collect256f.c -o collect256f.o
gcc -O3 -fomit-frame-pointer -funroll-loops -flto -o experiments/collect256f \
  collect256f.o "$root/sign.o" "$root/address.o" "$root/auxfunc.o" "$root/counters.o" \
  "$root/drng.o" "$root/hash_sm3.o" "$root/merkle.o" "$root/fors.o" \
  "$root/randombytes.o" "$root/thash_sm3_simple.o" "$root/utils.o" \
  "$root/utilsx1.o" "$root/wots.o" "$root/wotsx1.o"
gcc -O3 -fomit-frame-pointer -funroll-loops -Wall -Wextra -flto \
  -DPARAMS=cedrusc-sm3-256f -I"$root" -I"$root/params" -c forge256f.c -o forge256f.o
gcc -O3 -fomit-frame-pointer -funroll-loops -flto -o experiments/forge256f \
  forge256f.o "$root/sign.o" "$root/address.o" "$root/auxfunc.o" "$root/counters.o" \
  "$root/drng.o" "$root/hash_sm3.o" "$root/merkle.o" "$root/fors.o" \
  "$root/randombytes.o" "$root/thash_sm3_simple.o" "$root/utils.o" \
  "$root/utilsx1.o" "$root/wots.o" "$root/wotsx1.o"
gcc -O3 -fomit-frame-pointer -funroll-loops -Wall -Wextra -flto \
  -DPARAMS=cedrusc-sm3-256f -I"$root" -I"$root/params" -c verify256f.c -o verify256f.o
gcc -O3 -fomit-frame-pointer -funroll-loops -flto -o experiments/verify256f \
  verify256f.o "$root/sign.o" "$root/address.o" "$root/auxfunc.o" "$root/counters.o" \
  "$root/drng.o" "$root/hash_sm3.o" "$root/merkle.o" "$root/fors.o" \
  "$root/randombytes.o" "$root/thash_sm3_simple.o" "$root/utils.o" \
  "$root/utilsx1.o" "$root/wots.o" "$root/wotsx1.o"
