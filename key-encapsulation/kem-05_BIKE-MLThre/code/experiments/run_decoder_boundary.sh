#!/usr/bin/env bash
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
out="$here/model_trace"
for variant in stock128 l1json128; do
  root="$here/trace_$variant"
  inc="$root/bike_kem_ml"
  gcc -O2 -std=gnu11 -DVARIANT="\"$variant\"" -DSECURITY_BITS=128 \
    -DX86_64 -DUSE_NIST_RAND -DBIKE_MLTHRE_ENABLED=1 \
    -DBIKE_MLTHRE_DELTA_ENABLED=1 -DBIKE_MLTHRE_SAMPLING=1 \
    -DBIKE_L7_REFERENCE_DECODER=1 -DBIKE_L7_DYNAMIC_THRESHOLD=1 \
    -DBIKE_L7_EMPIRICAL_THRESHOLD=0 -DUSE_API_PKC_AUX=1 \
    -DSTANDALONE_IMPL=1 -I"$inc/include" -I"$inc/include/internal" \
    -I"$inc/src/third_party_src" -I"$inc/tests" \
    -I"$inc/tests/FromNIST" "$here/decoder_boundary_harness.c" \
    "$inc/tests/FromNIST/rng.c" "$root/build_kat_128/libbike_kem_ml.a" \
    -lcrypto -lm -o "$root/decoder_boundary_$variant"
  taskset -c 2 "$root/decoder_boundary_$variant" > "$out/${variant}_boundary.csv"
done
python3 - "$out/stock128_boundary.csv" "$out/l1json128_boundary.csv" \
  "$out/decoder_boundary_comparison.json" <<'PY'
import csv, json, sys
def read(path):
    with open(path, newline="") as f:
        lines=f.readlines()
    while lines and not lines[0].startswith("variant,"): lines.pop(0)
    return {(int(r["key"]),r["weight"],int(r["sample"])):r for r in csv.DictReader(lines)}
a,b=read(sys.argv[1]),read(sys.argv[2]); common=sorted(set(a)&set(b))
rows=[]
byweight={}
for k in common:
    x,y=a[k],b[k]
    if x["weight"]=="control": continue
    key=(x["ret"],x["match"],x["ss_fnv1a64"])
    other=(y["ret"],y["match"],y["ss_fnv1a64"])
    w=int(x["weight"])
    d=byweight.setdefault(str(w),{"samples":0,"stock_successes":0,"l1json_successes":0,"terminal_differences":0})
    d["samples"]+=1; d["stock_successes"]+=int(x["match"]=="1"); d["l1json_successes"]+=int(y["match"]=="1")
    if key!=other:
        d["terminal_differences"]+=1
        rows.append({"key":k[0],"weight":w,"sample":k[2],"ct_fnv1a64":x["ct_fnv1a64"],"stock":key,"l1json":other})
json.dump({"schema":"bike-mlthre-controlled-weight-terminal-search/v1","common_rows":len(common),"controls":[a[k]["control_match"] for k in common if a[k]["weight"]=="control"],"by_weight":byweight,"terminal_differences":rows,"limits":["Ciphertexts follow the original equation for explicit chosen errors but errors are not H(m)-derived.","A success means the decoder recovered the chosen e and c1-derived m; fallback is the specified invalid-ciphertext behavior.","This finite weight grid is a bounded search, not a decoder-radius theorem."]},open(sys.argv[3],"w"),indent=2,sort_keys=True)
print(json.dumps({"common_rows":len(common),"controls":len([1 for k in common if a[k]["weight"]=="control"]),"diffs":len(rows)}))
PY
