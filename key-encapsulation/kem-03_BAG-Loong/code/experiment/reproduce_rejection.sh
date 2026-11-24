#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
IMPL="$ROOT/original/Implementations/Reference_Implementation/Loong-Block-ms-128"
CC_BIN=${CC:-cc}

cd "$IMPL"
make -j2
./bin/KAT_KEM >/dev/null
sha256sum output/KAT_KEM_BAG-Loong-128.txt

SOURCES="
lib/rbc-47/rbc_elt.c
lib/rbc-47/rbc_vec.c
src/KEM_AlgorithmInstance.c
src/augabidulin.c
src/ct_util.c
src/gabidulin.c
src/loong_api_random.c
src/loong_hash.c
src/loong_kem.c
src/loong_pke.c
src/loong_support.c
src/loong_xof_reader.c
src/parsing.c
src/qpoly.c
lib/api_pkc/auxfunc.c
lib/api_pkc/drng.c
"

# shellcheck disable=SC2086
$CC_BIN -std=c99 -O2 -Wall -Wextra \
	-Isrc -Ilib/api_pkc -Ilib/rbc-47 \
	$SOURCES "$ROOT/kem_rejection_probe.c" -o "$ROOT/kem_rejection_probe"

"$ROOT/kem_rejection_probe"
