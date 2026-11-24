#!/usr/bin/env python3
import pathlib
import os
import pycryptosat

PATH_MUL = (
    1, 2, 4, 8, 3, 6, 12, 11, 5, 10, 7, 14, 15, 13, 9
)
MUL = [[0] * 16 for _ in range(16)]
for i in range(15):
    for j in range(15):
        MUL[PATH_MUL[i]][PATH_MUL[j]] = PATH_MUL[(i + j) % 15]

lines = pathlib.Path("map.txt").read_text().splitlines()
perm = [int(x) for x in lines[0].split()[1:]]
target = [int(x) for x in lines[1].split()[1:]]
terms = [[] for _ in range(104)]
for line in lines[2:]:
    _, eq, a, b, coeff = line.split()
    terms[int(eq)].append((int(a), int(b), int(coeff)))

solver = pycryptosat.Solver()
next_var = 1
x = [[0] * 4 for _ in range(200)]
for i in range(200):
    for bit in range(4):
        x[i][bit] = next_var
        next_var += 1

and_vars = {}
def and_var(a, b):
    global next_var
    key = (a, b) if a < b else (b, a)
    if key in and_vars:
        return and_vars[key]
    out = next_var
    and_vars[key] = out
    next_var += 1
    # out <-> a AND b
    solver.add_clause([-out, a])
    solver.add_clause([-out, b])
    solver.add_clause([out, -a, -b])
    return out

def inc_var():
    global next_var
    out = next_var
    next_var += 1
    return out

and_vars = {}
next_var = 801
for eq in range(104):
    for out_bit in range(4):
        parity = []
        for a, b, coeff in terms[eq]:
            for ib in range(4):
                for jb in range(4):
                    product = MUL[coeff][MUL[1 << ib][1 << jb]]
                    if product & (1 << out_bit):
                        parity.append(and_var(x[a][ib], x[b][jb]))
        solver.add_xor_clause(parity, bool((target[eq] >> out_bit) & 1))

# Require a different signature from the KAT witness.
sig = pathlib.Path("sig.bin").read_bytes()
secret = [0] * 200
for pub_i, sec_i in enumerate(perm):
    nibble = ((sig[pub_i // 2] >> (4 * (pub_i & 1))) & 15)
    secret[sec_i] = nibble
different = []
for i in range(200):
    for bit in range(4):
        different.append(-x[i][bit] if (secret[i] >> bit) & 1 else x[i][bit])
if os.environ.get("WITHOUT_DIFFERENT") != "1":
    solver.add_clause(different)

print("vars", next_var - 1, "and_vars", len(and_vars))
sat, assignment = solver.solve()
print("sat", sat)
if sat:
    model = set(i for i, val in enumerate(assignment) if val is True)
    vals = [sum((1 << bit) for bit in range(4) if x[i][bit] in model)
            for i in range(200)]
    public = [0] * 200
    for sec_i, pub_i in enumerate(perm):
        public[pub_i] = vals[sec_i]
    out = bytearray(100)
    for i, val in enumerate(public):
        out[i // 2] |= val << (4 * (i & 1))
    out += sig[100:]
    pathlib.Path("forged_sig.bin").write_bytes(out)
    print("forged", out.hex())
