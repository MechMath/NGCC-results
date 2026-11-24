#!/usr/bin/env python3
"""Exact finite-field rank probe for the VDOO central map.

This does not use the private key generation RNG.  It instantiates the
documented coefficient supports with deterministic pseudo-random field
coefficients and checks the central rank identities.  Input/output changes
of basis preserve every rank computed here.
"""

import argparse
import random


def gf16_mul(a, b):
    def gf4_mul(x, y):
        r = x * (y & 1)
        z = ((x << 1) ^ ((x >> 1) * 7)) & 3
        return r ^ (z * (y >> 1))

    a0, a1 = a & 3, a >> 2
    b0, b1 = b & 3, b >> 2
    a0b0 = gf4_mul(a0, b0)
    a1b1 = gf4_mul(a1, b1)
    cross = gf4_mul(a0 ^ a1, b0 ^ b1) ^ a0b0 ^ a1b1
    return ((cross ^ a1b1) << 2) ^ a0b0 ^ (gf4_mul(a1b1, 2))


def gf256_mul(a, b):
    a0, a1 = a & 15, a >> 4
    b0, b1 = b & 15, b >> 4
    a0b0 = gf16_mul(a0, b0)
    a1b1 = gf16_mul(a1, b1)
    cross = gf16_mul(a0 ^ a1, b0 ^ b1) ^ a0b0 ^ a1b1
    x8 = gf16_mul(a1b1, 8)
    return ((cross ^ a1b1) << 4) ^ a0b0 ^ x8


def rank(a):
    a = [row[:] for row in a]
    rows = len(a)
    cols = len(a[0]) if rows else 0
    r = 0
    for c in range(cols):
        p = next((i for i in range(r, rows) if a[i][c]), None)
        if p is None:
            continue
        a[r], a[p] = a[p], a[r]
        inv = 0
        # The field polynomial is not integer modulo arithmetic.
        for v in range(1, 256):
            if MUL[a[r][c]][v] == 1:
                inv = v
                break
        a[r] = [MUL[inv][x] for x in a[r]]
        for i in range(rows):
            if i != r and a[i][c]:
                f = a[i][c]
                a[i] = [x ^ MUL[f][y] for x, y in zip(a[i], a[r])]
        r += 1
        if r == rows:
            break
    return r


MUL = [[gf256_mul(i, j) for j in range(256)] for i in range(256)]


def central_terms(v, d, o1, o2, rng):
    n = v + d + o1 + o2
    v2 = v + d
    v3 = v + d + o1
    forms = []
    for k in range(n - v):
        terms = {}
        if k < d:
            diag = v + k
            for i in range(diag):
                terms[i, diag] = rng.randrange(1, 256)
            for i in range(diag):
                for j in range(i, diag):
                    terms[i, j] = rng.randrange(1, 256)
        elif k < d + o1:
            oil = v2 + (k - d)
            for i in range(v2):
                for j in range(i, v2):
                    terms[i, j] = rng.randrange(1, 256)
            for i in range(v2):
                terms[i, oil] = rng.randrange(1, 256)
        else:
            oil = v3 + (k - d - o1)
            for i in range(v3):
                for j in range(i, v3):
                    terms[i, j] = rng.randrange(1, 256)
            for i in range(v3):
                terms[i, oil] = rng.randrange(1, 256)
        forms.append(terms)
    return forms


def symmetric_matrix(terms, n):
    a = [[0] * n for _ in range(n)]
    for (i, j), c in terms.items():
        if i == j:
            continue
        a[i][j] = c
        a[j][i] = c
    return a


def matvec(a, x):
    out = []
    for row in a:
        z = 0
        for c, v in zip(row, x):
            z ^= MUL[c][v]
        out.append(z)
    return out


def random_vec(n, rng):
    while True:
        x = [rng.randrange(256) for _ in range(n)]
        if any(x):
            return x


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--v", type=int, default=67)
    ap.add_argument("--d", type=int, default=16)
    ap.add_argument("--o1", type=int, default=14)
    ap.add_argument("--o2", type=int, default=40)
    ap.add_argument("--seed", type=int, default=3301)
    ap.add_argument("--samples", type=int, default=3)
    args = ap.parse_args()
    assert args.v == 67 and args.d == 16 and args.o1 == 14 and args.o2 == 40
    rng = random.Random(args.seed)
    m = args.d + args.o1 + args.o2
    n = args.v + m
    forms = central_terms(args.v, args.d, args.o1, args.o2, rng)
    mats = [symmetric_matrix(f, n) for f in forms]

    print({"parameter": "VDOO-128", "n": n, "m": m, "field": "GF(256)"})
    print("individual_matrix_ranks", [rank(a) for a in mats[:5]],
          "...", [rank(a) for a in mats[-5:]])

    def combo(weights):
        out = [[0] * n for _ in range(n)]
        for w, a in zip(weights, mats):
            if not w:
                continue
            for i in range(n):
                for j in range(n):
                    out[i][j] ^= MUL[w][a[i][j]]
        return out

    for label, lo, hi in [
        ("D_only", 0, args.d),
        ("O1_only", args.d, args.d + args.o1),
        ("O2_only", args.d + args.o1, m),
        ("D_O1", 0, args.d + args.o1),
        ("all", 0, m),
    ]:
        vals = []
        for _ in range(args.samples):
            w = [0] * m
            for i in range(lo, hi):
                w[i] = rng.randrange(1, 256)
            vals.append(rank(combo(w)))
        print("combined_matrix_rank", label, vals)

    for j in range(args.samples):
        a = [0] * n
        for i in range(args.v + args.d + args.o1, n):
            a[i] = rng.randrange(1, 256)
        derivative = [matvec(mat, a) for mat in mats]
        hidden_rank = rank(derivative)
        a = random_vec(n, rng)
        derivative = [matvec(mat, a) for mat in mats]
        generic_rank = rank(derivative)
        print("differential_rank", {"sample": j, "hidden_O2": hidden_rank,
                                     "generic": generic_rank})

    # Intersection of all kernels is computed by stacking matrices.  This
    # tests the tempting but false claim that O2 itself is the common kernel.
    stacked = []
    for a in mats:
        stacked.extend(a)
    print("common_kernel_all_Hessians", n - rank(stacked))

    # Verify A_j kills every O2 vector exactly for the 30 D/O1 matrices.
    killed = True
    for j in range(args.d + args.o1):
        for z in range(args.v + args.d + args.o1, n):
            if any(mats[j][i][z] for i in range(n)):
                killed = False
                break
    print("D_O1_matrices_kill_O2", killed)

    # Stack the 30 hidden D/O1 matrices; their common kernel has dimension 40.
    hidden30 = []
    for a in mats[:args.d + args.o1]:
        hidden30.extend(a)
    print("common_kernel_hidden_DO1", n - rank(hidden30))


if __name__ == "__main__":
    main()
