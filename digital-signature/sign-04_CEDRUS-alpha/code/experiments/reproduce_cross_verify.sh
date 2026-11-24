#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

cmp experiments/KAT_160f_archive.txt \
    experiments/submitted_160f/output/KAT_SIG_CEDRUSALPHA-160f.txt

make -C experiments/submitted_160f clean
make -C experiments/submitted_160f OPTFLAGS='-O2'
make -C experiments/control_chain32_160f clean
make -C experiments/control_chain32_160f OPTFLAGS='-O2'

# The supplied KAT program writes its own output file. Keep its console message separate.
experiments/control_chain32_160f/KAT_SIG \
    > experiments/control_chain32_160f/kat_stdout.txt

cd experiments

common_objects=(
    auxfunc.o drng.o fors.o hash_sm3.o merkle.o randombytes.o sign.o
    thash_sm3_simple.o utils.o utilsx1.o wots.o wotsx1.o
)

gcc -O2 -Isubmitted_160f kat_cross_verify.c submitted_160f/address.o \
    "${common_objects[@]/#/submitted_160f/}" -o submitted_cross_verify
gcc -O2 -Icontrol_chain32_160f kat_cross_verify.c control_chain32_160f/address.o \
    "${common_objects[@]/#/control_chain32_160f/}" -o control_cross_verify

./submitted_cross_verify KAT_160f_archive.txt > submitted_on_submitted.txt
./submitted_cross_verify control_chain32_160f/output/KAT_SIG_CEDRUSALPHA-160f.txt \
    > submitted_on_control.txt
./control_cross_verify KAT_160f_archive.txt > control_on_submitted.txt
./control_cross_verify control_chain32_160f/output/KAT_SIG_CEDRUSALPHA-160f.txt \
    > control_on_control.txt

python3 verify_control_kats.py

grep -q 'summary entries=10 accepted=10 rejected=0' submitted_on_submitted.txt
grep -q 'summary entries=10 accepted=0 rejected=10' submitted_on_control.txt
grep -q 'summary entries=10 accepted=0 rejected=10' control_on_submitted.txt
grep -q 'summary entries=10 accepted=10 rejected=0' control_on_control.txt

printf '%s\n' \
    'submitted verifier / submitted KAT: 10 accepted, 0 rejected' \
    'submitted verifier / control KAT: 0 accepted, 10 rejected' \
    'control verifier / submitted KAT: 0 accepted, 10 rejected' \
    'control verifier / control KAT: 10 accepted, 0 rejected'
