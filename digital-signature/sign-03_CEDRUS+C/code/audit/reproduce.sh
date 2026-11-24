#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
ZIP=${1:-"$ROOT/audit/input/cedrus+c.zip"}
EVIDENCE=${2:-"$ROOT/audit/evidence/oracle-records"}
EXPECTED_ZIP=a31de849cf0a0703a4e57decbdf4d97b100d00dc74756feaded2c04a7593e110
EXPECTED_KAT=310d1dac607084de9e97c493a3e6f4bf97c47532a20b6b0ef4bb52ec84bf1bea

actual_zip=$(sha256sum "$ZIP" | awk '{print $1}')
test "$actual_zip" = "$EXPECTED_ZIP"

work=$(mktemp -d "$ROOT/audit/work/repro.XXXXXX")
python3 -m zipfile -e "$ZIP" "$work"
ref="$work/Implementations/Reference_Implementation/CEDRUSC-160f"

make -C "$ref" clean all
(cd "$ref" && ./KAT_SIG)
actual_kat=$(sha256sum "$ref/output/KAT_SIG_CEDRUSC-160f.txt" | awk '{print $1}')
test "$actual_kat" = "$EXPECTED_KAT"

mkdir -p "$ROOT/audit/bin"
gcc -O2 -Wall -Wextra -DPARAMS=cedrusc-sm3-160f -I"$ref" \
    -o "$ROOT/audit/bin/audit_records" "$ROOT/audit/audit_records.c" \
    "$ref"/sign.o "$ref"/address.o "$ref"/auxfunc.o "$ref"/counters.o \
    "$ref"/drng.o "$ref"/hash_sm3.o "$ref"/merkle.o "$ref"/fors.o \
    "$ref"/randombytes.o "$ref"/SIG_AlgorithmInstance.o \
    "$ref"/thash_sm3_simple.o "$ref"/utils.o "$ref"/utilsx1.o \
    "$ref"/wots.o "$ref"/wotsx1.o

"$ROOT/audit/bin/audit_records" "$EVIDENCE"

gcc -O2 -Wall -Wextra -DPARAMS=cedrusc-sm3-160f -I"$ref" \
    -o "$ROOT/audit/bin/verify_retained_evidence" \
    "$ROOT/audit/evidence/verify_forced_tree.c" \
    "$ref"/sign.o "$ref"/address.o "$ref"/auxfunc.o "$ref"/counters.o \
    "$ref"/drng.o "$ref"/hash_sm3.o "$ref"/merkle.o "$ref"/fors.o \
    "$ref"/randombytes.o "$ref"/SIG_AlgorithmInstance.o \
    "$ref"/thash_sm3_simple.o "$ref"/utils.o "$ref"/utilsx1.o \
    "$ref"/wots.o "$ref"/wotsx1.o

"$ROOT/audit/bin/verify_retained_evidence" "$EVIDENCE"
