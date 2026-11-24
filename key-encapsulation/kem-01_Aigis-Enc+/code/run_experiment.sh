#!/usr/bin/env bash
set -euo pipefail

ZIP=${AIGIS_ZIP:-/home/mmat/mmat-preview/runs/ngcc-kem-01-ds01/slots/orch-graph/orch/materials/Aigis-Enc+.zip}
SRC=$(mktemp -d /tmp/aigis-ref.XXXXXX)
OUT=${1:-./experiment-ref-i}
PARAMS=${PARAMS:-1}

TRIALS=${TRIALS:-10000}

trap 'rm -rf "$SRC"' EXIT
python3 - "$ZIP" "$SRC" <<'PY'
import pathlib
import sys
import zipfile

archive, destination = sys.argv[1:]
prefix = "Implementations/Reference_Implementation/Aigis-Enc+-I/"
root = pathlib.Path(destination)
with zipfile.ZipFile(archive) as z:
    for name in z.namelist():
        if name.startswith(prefix) and not name.endswith("/"):
            out = root / name[len(prefix):]
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_bytes(z.read(name))
PY

gcc -DPARAMS="$PARAMS" -DUSE_SHA3 -DTRIALS="$TRIALS" -O2 -g -fno-omit-frame-pointer -std=c99 \
  -I"$SRC" \
  "$SRC"/cbd.c "$SRC"/fips202.c "$SRC"/poly.c "$SRC"/reduce.c \
  "$SRC"/precomp.c "$SRC"/ntt.c "$SRC"/polyvec.c "$SRC"/owcpa.c \
  "$SRC"/kem.c "$SRC"/verify.c "$SRC"/hashkdf.c "$SRC"/gen_a.c \
  "$SRC"/kat_test/auxfunc.c "$SRC"/kat_test/KEM_AlgorithmInstance.c \
  "$SRC"/kat_test/drng.c "$SRC"/pack.c "$SRC"/randombytes.c \
  experiment_ref_dec.c -o "$OUT"

./"$OUT"
