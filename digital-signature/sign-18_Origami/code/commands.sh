#!/bin/sh
set -eu

# Extract exact reference source from the hash-pinned submission ZIP.
python3 - <<'PY'
from pathlib import Path
import zipfile
z = zipfile.ZipFile("Origami.zip")
prefix = "Implementations and Test_Vectors/Implementations/Reference_Implementation/Origami-256/"
out = Path("origami256-ref")
out.mkdir(exist_ok=True)
for info in z.infolist():
    if info.filename.startswith(prefix) and not info.is_dir():
        dest = out / info.filename[len(prefix):]
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(z.read(info))
PY

gcc -std=c11 -O3 -DORIGAMI_OPT=REF -Iorigami256-ref \
  -o verify_files_original verify_files.c \
  origami256-ref/SIG_AlgorithmInstance.c origami256-ref/drng.c \
  origami256-ref/auxfunc.c origami256-ref/symmetric_iccs.c \
  origami256-ref/origami_ref.c origami256-ref/aes.c

gcc -std=c11 -O3 -DORIGAMI_OPT=REF -DORIGAMI_SOURCE='"origami_ref.c"' \
  -I origami256-ref -o dump_public_map \
  /home/mmat/mmat-preview/runs/ngcc-sign-18-ds01/slots/orch-graph/orch/tools/origami_probe.c \
  origami256-ref/auxfunc.c origami256-ref/symmetric_iccs.c origami256-ref/aes.c

./verify_files_original \
  /home/mmat/mmat-preview/runs/ngcc-sign-18-ds01/slots/orch-graph/orch/origami256/pk.bin \
  /home/mmat/mmat-preview/runs/ngcc-sign-18-ds01/slots/orch-graph/orch/fresh-message.bin \
  /home/mmat/mmat-preview/runs/ngcc-sign-18-ds01/slots/orch-graph/orch/fresh-forgery-256/signature.bin

./dump_public_map dump \
  /home/mmat/mmat-preview/runs/ngcc-sign-18-ds01/slots/orch-graph/orch/origami256/pk.bin \
  /home/mmat/mmat-preview/runs/ngcc-sign-18-ds01/slots/orch-graph/orch/fresh-message.bin \
  /home/mmat/mmat-preview/runs/ngcc-sign-18-ds01/slots/orch-graph/orch/fresh-forgery-256/signature.bin \
  > map-reproduced.txt

python3 /home/mmat/mmat-preview/runs/ngcc-sign-18-ds01/slots/orch-graph/orch/forge_any_salt.py \
  --map "$PWD/map-reproduced.txt" \
  --pk /home/mmat/mmat-preview/runs/ngcc-sign-18-ds01/slots/orch-graph/orch/origami256/pk.bin \
  --message "$PWD/fresh-message-2.bin" \
  --hash-target "$PWD/dump_public_map" --hash-command-mode hash \
  --verifier "$PWD/verify_files_original" --verifier-command-mode verify \
  --security-bits 256 --out-dir "$PWD/fresh-forgery-2b"

