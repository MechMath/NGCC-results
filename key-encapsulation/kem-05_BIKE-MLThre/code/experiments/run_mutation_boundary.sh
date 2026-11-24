#!/usr/bin/env bash
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; out="$here/model_trace"
for variant in stock128 l1json128; do
 root="$here/trace_$variant"; inc="$root/bike_kem_ml"
 gcc -O2 -std=gnu11 -DVARIANT="\"$variant\"" -DSECURITY_BITS=128 \
  -DX86_64 -DUSE_NIST_RAND -DBIKE_MLTHRE_ENABLED=1 -DBIKE_MLTHRE_DELTA_ENABLED=1 \
  -DBIKE_MLTHRE_SAMPLING=1 -DBIKE_L7_REFERENCE_DECODER=1 -DBIKE_L7_DYNAMIC_THRESHOLD=1 \
  -DBIKE_L7_EMPIRICAL_THRESHOLD=0 -DUSE_API_PKC_AUX=1 -DSTANDALONE_IMPL=1 \
  -I"$inc/include" -I"$inc/include/internal" -I"$inc/src/third_party_src" \
  -I"$inc/tests" -I"$inc/tests/FromNIST" "$here/mutation_boundary_harness.c" \
  "$inc/tests/FromNIST/rng.c" "$root/build_kat_128/libbike_kem_ml.a" -lcrypto -lm \
  -o "$root/mutation_boundary_$variant"
 taskset -c 2 "$root/mutation_boundary_$variant" > "$out/${variant}_mutation.csv"
done
python3 - "$out/stock128_mutation.csv" "$out/l1json128_mutation.csv" "$out/mutation_comparison.json" <<'PY'
import csv,json,sys
def read(p):
 r=list(csv.DictReader(open(p)))
 return {(int(x["key"]),x["bits"],int(x["rep"])):x for x in r}
a,b=read(sys.argv[1]),read(sys.argv[2]); common=sorted(set(a)&set(b)); diffs=[]; controls=[]
for k in common:
 x,y=a[k],b[k]
 if x["bits"]=="control": controls.append((x["control_match"],y["control_match"])); continue
 q=(x["ct_fnv1a64"],x["ss_fnv1a64"],x["match"]); z=(y["ct_fnv1a64"],y["ss_fnv1a64"],y["match"])
 # ct is constructed independently and must agree before a terminal comparison is meaningful.
 if q!=z: diffs.append({"key":k[0],"bits":int(x["bits"]),"rep":k[2],"stock":q,"l1json":z,"same_ciphertext":x["ct_fnv1a64"]==y["ct_fnv1a64"]})
json.dump({"schema":"bike-mlthre-mutation-terminal-search/v1","rows":len(common),"controls":controls,"terminal_differences":diffs,"limits":["Base ciphertexts are generated from H(m) with the original equation.","Only finite deterministic multi-bit c0 perturbations are covered.","A pair is comparable only when both independent constructions yield the same ciphertext hash."]},open(sys.argv[3],"w"),indent=2,sort_keys=True)
print(json.dumps({"rows":len(common),"controls":len(controls),"differences":len(diffs),"same_ct_differences":sum(d["same_ciphertext"] for d in diffs)}))
PY
