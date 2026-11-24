#!/bin/sh
set -eu

run_root=/home/mmat/mmat-preview/runs/ngcc-sign-09-ds01
here=/home/mmat/mmat-preview/runs/ngcc-sign-09-ds01/run/slots/caf15ec0537546de/source-acquisition-proof
python3 "$here/audit.py" --output "$here/evidence.json"
cd "$here"
sha256sum -c evidence.json.sha256
