#!/bin/sh
set -eu

slot=/home/mmat/mmat-preview/runs/ngcc-kem-03-ds01/run/slots/8ca773ab7c2e45ba
impl="$slot/original_extracted/Implementations/Reference_Implementation/Loong-Block-ms-128"

if [ ! -f "$impl/build/src/loong_kem.o" ]; then
	(cd "$impl" && make -j2)
fi

cd "$impl"
cc -std=c99 -O2 -Isrc -Ilib/api_pkc -Ilib/rbc-47 \
	"$slot/experiment/kem_layer_probe.c" \
	build/lib/rbc-47/rbc_elt.o \
	build/lib/rbc-47/rbc_vec.o \
	build/src/KEM_AlgorithmInstance.o \
	build/src/augabidulin.o \
	build/src/ct_util.o \
	build/src/gabidulin.o \
	build/src/loong_api_random.o \
	build/src/loong_hash.o \
	build/src/loong_kem.o \
	build/src/loong_pke.o \
	build/src/loong_support.o \
	build/src/loong_xof_reader.o \
	build/src/parsing.o \
	build/src/qpoly.o \
	build/lib/api_pkc/auxfunc.o \
	build/lib/api_pkc/drng.o \
	-o "$slot/experiment/kem_layer_probe"

"$slot/experiment/kem_layer_probe"
