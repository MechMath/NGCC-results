#!/usr/bin/env bash
set -eu

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

mkdir -p original work/bin work/out

zip='original/BiT.zip'
spec='original/sign-02-spec.pdf'
test "$(sha256sum "$zip" | cut -d' ' -f1)" = \
  698fbe834279a4100a66c20f3e0b634c738e1150936acf74b55efc6db6975e8d
test "$(sha256sum "$spec" | cut -d' ' -f1)" = \
  28e942ee1baa7b686271420d56bea370c65891b4b57ef4045424f8a52dd0ccca

python3 -m zipfile -e "$zip" original/BiT

refdir='original/BiT/Implementations/Reference_Implementation/BiT-128'
avxdir='original/BiT/Implementations/Optimized_Implementation/BiT-128-avx2'

ref_srcs=()
for f in "$refdir"/*.c
do
  [ "$(basename "$f")" = KAT_SIG.c ] || ref_srcs+=("$f")
done

avx_srcs=()
for f in "$avxdir"/*.c
do
  [ "$(basename "$f")" = KAT_SIG.c ] || avx_srcs+=("$f")
done

gcc -std=c99 -O2 -I"$refdir" work/cross_driver.c "${ref_srcs[@]}" \
  -o work/bin/ref_cross -Wno-unused-function
gcc -std=c99 -O3 -march=x86-64 -mavx2 -mtune=native \
  -fomit-frame-pointer -DASM_ALIASES -I"$avxdir" \
  work/cross_driver.c "${avx_srcs[@]}" \
  "$avxdir"/f1600x4.S "$avxdir"/ntt.S "$avxdir"/intt.S \
  "$avxdir"/pointwise.S -o work/bin/avx_cross -Wno-unused-function

work/bin/ref_cross gen work/out/ref
work/bin/avx_cross gen work/out/avx
cmp work/out/ref.pk work/out/avx.pk
cmp work/out/ref.sk work/out/avx.sk
cmp work/out/ref.msg work/out/avx.msg
cmp work/out/ref.sig work/out/avx.sig
work/bin/ref_cross verify work/out/avx
work/bin/avx_cross verify work/out/ref

python3 - <<'PY'
from pathlib import Path
text = Path('original/BiT/Test_Vectors/KAT_SIG_BiT-128.txt').read_text()
out = Path('work/out/kat')
out.mkdir(exist_ok=True)
records = []
cur = {}
for line in text.splitlines():
    if ' = ' not in line:
        continue
    key, value = line.split(' = ', 1)
    if key == 'Count':
        if cur:
            records.append(cur)
        cur = {'Count': value}
    else:
        cur[key] = value
if cur:
    records.append(cur)
D = 1681
maximum = 0
for record in records:
    i = int(record['Count'])
    prefix = out / f'kat{i:02d}'
    for key, suffix in [('PK', 'pk'), ('M', 'msg'), ('Sn', 'sig')]:
        (out / f'{prefix.name}.{suffix}').write_bytes(bytes.fromhex(record[key]))
    pk = bytes.fromhex(record['PK'])
    for poly in range(3):
        off = 16 + 344 * poly
        word = int.from_bytes(pk[off:off + 344], 'little')
        for block in range(64):
            value = (word >> (43 * block)) & ((1 << 43) - 1)
            assert value < D**4
            maximum = max(maximum, value)
assert len(records) == 10
print(f'KAT records={len(records)} b1_words={10*3*64} max={maximum} D4-1={D**4-1}')
PY

for i in 00 01 02 03 04 05 06 07 08 09
do
  work/bin/ref_cross verify "work/out/kat/kat$i"
  work/bin/avx_cross verify "work/out/kat/kat$i"
done

gcc -std=c99 -O2 -I"$refdir" work/rebind_driver.c \
  "${ref_srcs[@]}" -o work/bin/ref_rebind -Wno-unused-function
work/bin/ref_rebind work/out/ref
mkdir -p work/out/mutant_orig work/out/mutant_rebound
cp work/out/ref.mutpk work/out/mutant_orig/m.pk
cp work/out/ref.msg work/out/mutant_orig/m.msg
cp work/out/ref.sig work/out/mutant_orig/m.sig
cp work/out/ref.mutpk work/out/mutant_rebound/m.pk
cp work/out/ref.msg work/out/mutant_rebound/m.msg
cp work/out/ref.mutsig work/out/mutant_rebound/m.sig

printf 'original signature under mutated pk, reference: '
work/bin/ref_cross verify work/out/mutant_orig/m
printf 'original signature under mutated pk, AVX2: '
work/bin/avx_cross verify work/out/mutant_orig/m
printf 'transcript-rebound signature under mutated pk, reference: '
work/bin/ref_cross verify work/out/mutant_rebound/m
printf 'transcript-rebound signature under mutated pk, AVX2: '
work/bin/avx_cross verify work/out/mutant_rebound/m
