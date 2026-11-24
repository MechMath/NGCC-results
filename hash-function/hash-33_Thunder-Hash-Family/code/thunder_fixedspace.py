#!/usr/bin/env python3
"""Exact small-state analysis of the fixed space of Thunder-p's linear layer."""

from collections import defaultdict


TAU = [
    [45, 40, 34, 48, 6],
    [33, 52, 5, 30, 18],
    [13, 19, 0, 61, 49],
    [1, 47, 2, 8, 17],
    [27, 9, 37, 38, 43],
]
TY = [41, 50, 6, 10, 27]
RC = [
    0x0000000000000001,
    0x0000000000000003,
    0x000000000000000A,
    0x0000000000000088,
    0x0000000000008081,
    0x0000000000008002,
    0x0000000000000009,
    0x0000000000000083,
    0x000000000000800A,
    0x0000000000000089,
    0x0000000000008083,
    0x000000000000800B,
]


def pos(x, y, z):
    return 64 * (5 * y + x) + z


def rho(s):
    out = 0
    for x in range(5):
        for y in range(5):
            for z in range(64):
                if (s >> pos(x, y, (z + TAU[x][y]) % 64)) & 1:
                    out |= 1 << pos(x, y, z)
    return out


def theta(s):
    p = [[0] * 64 for _ in range(5)]
    q = [[0] * 64 for _ in range(5)]
    for x in range(5):
        for z in range(64):
            p[x][z] = sum(((s >> pos(x, y, z)) & 1) for y in range(5)) & 1
            q[x][z] = sum(((s >> pos(x, y, (z + TY[y]) % 64)) & 1) for y in range(5)) & 1
    out = s
    u = 26
    for x in range(5):
        for y in range(5):
            for z in range(64):
                e = p[x][(z + u) % 64] ^ p[(x - 1) % 5][(z + u + 1) % 64]
                f = q[(x + 1) % 5][(z + u + TY[y]) % 64] ^ q[(x - 2) % 5][
                    (z + u + TY[y] + 36) % 64
                ]
                if e ^ f:
                    out ^= 1 << pos(x, y, z)
    return out


def pi(s):
    out = 0
    for x in range(5):
        for y in range(5):
            xo, yo = y, (2 * x + 3 * y + 2) % 5
            for z in range(64):
                if (s >> pos(x, y, z)) & 1:
                    out |= 1 << pos(xo, yo, z)
    return out


def linear(s):
    return pi(theta(rho(s)))


def psi(s):
    out = 0
    for x in range(5):
        for z in range(64):
            a = [((s >> pos(x, y, z)) & 1) for y in range(5)]
            for y in range(5):
                b = a[(y + 3) % 5] ^ (
                    (1 ^ a[(y + 1) % 5])
                    & a[(y + 2) % 5]
                    & (1 ^ a[(y + 4) % 5])
                )
                if b:
                    out |= 1 << pos(x, y, z)
    return out


def iota(s, rnd):
    return s ^ RC[rnd]


def round_(s, rnd):
    return psi(linear(iota(s, rnd)))


def perm(s):
    for rnd in range(12):
        s = round_(s, rnd)
    return s


def gf2_nullspace(rows, n):
    pivots = {}
    for row in rows:
        while row:
            p = row.bit_length() - 1
            if p in pivots:
                row ^= pivots[p]
            else:
                # Keep the row-reduced echelon form: remove the new pivot from
                # every old row as well, so other pivot coordinates vanish.
                for q in list(pivots):
                    if (pivots[q] >> p) & 1:
                        pivots[q] ^= row
                pivots[p] = row
                break
    basis = []
    for free in range(n):
        if free in pivots:
            continue
        v = 1 << free
        for p in sorted(pivots):
            if (pivots[p] & v).bit_count() & 1:
                v |= 1 << p
        basis.append(v)
    return basis, pivots


def span(basis):
    vals = [0]
    for b in basis:
        vals += [v ^ b for v in vals]
    return vals


def rank(vectors):
    basis = {}
    for row in vectors:
        while row:
            p = row.bit_length() - 1
            if p in basis:
                row ^= basis[p]
            else:
                basis[p] = row
                break
    return len(basis)


def support(v):
    return tuple(i for i in range(1600) if (v >> i) & 1)


def fmt_vec(v):
    vals = []
    for x in range(5):
        for y in range(5):
            word = sum(((v >> pos(x, y, z)) & 1) << z for z in range(64))
            vals.append(f"{word:016x}")
    return " ".join(vals)


def main():
    # L+I is represented by its columns/images of unit vectors, then transposed
    # to obtain the row matrix whose kernel is Fix(L).
    columns = [(linear(1 << i)) ^ (1 << i) for i in range(1600)]
    rows = [0] * 1600
    for i, col in enumerate(columns):
        bits = col
        while bits:
            low = bits & -bits
            j = low.bit_length() - 1
            rows[j] |= 1 << i
            bits ^= low
    wbasis, pivots = gf2_nullspace(rows, 1600)
    assert len(pivots) == 1597
    assert len(wbasis) == 3
    print("rank(L+I)", len(pivots), "dim Fix(L)", len(wbasis))
    for i, v in enumerate(wbasis):
        print("W", i, fmt_vec(v))
        for j, row in enumerate(rows):
            if (row & v).bit_count() & 1:
                print("bad nullspace row", i, j)
                raise SystemExit(1)
    vals = span(wbasis)
    for v in vals:
        assert linear(v) == v
        img = psi(v)
        print("x", f"{v:0400x}", "psi(x) xor x", f"{img ^ v:0400x}")
        print("psi(x) in W", img in vals, "fixed-by-psi", img == v)
    print("psi(W) subset W", all(psi(v) in vals for v in vals))
    print("psi(W) intersect W", sorted(psi(v) for v in vals) == sorted(vals))

    # V consists of states constant across all 25 lanes separately at each z.
    uniform_basis = []
    for z in range(64):
        v = 0
        for x in range(5):
            for y in range(5):
                v |= 1 << pos(x, y, z)
        uniform_basis.append(v)
    def in_uniform(v):
        for z in range(64):
            bits = {(v >> pos(x, y, z)) & 1 for x in range(5) for y in range(5)}
            if len(bits) != 1:
                return False
        return True

    print("psi(V) subset V", all(in_uniform(psi(v)) for v in uniform_basis))
    lv = [linear(v) for v in uniform_basis]
    print("dim V", rank(uniform_basis), "dim L(V)", rank(lv))
    intersection = []
    # Since dimensions are only 64, solve L(V) intersect V with a joint matrix by
    # enumerating combinations after elimination in the separate bases.
    piv = {}
    for j, row in enumerate(uniform_basis):
        while row:
            p = row.bit_length() - 1
            if p in piv:
                row ^= piv[p][0]
            else:
                piv[p] = (row, 1 << j)
                break
    for j, row in enumerate(lv):
        combo = 1 << j
        while row:
            p = row.bit_length() - 1
            if p in piv:
                row ^= piv[p][0]
                combo ^= piv[p][1]
            else:
                piv[p] = (row, combo)
                intersection.append(combo)
                break
    print("dim L(V) intersect V", 64 - len(intersection))
    # Constants are supported once per round; test whether constants preserve W
    # and whether each actual round maps W into W.
    for rnd in range(12):
        c_in_w = RC[rnd] in vals
        mapped = [round_(v, rnd) in vals for v in vals]
        print("round", rnd, "RC in W", c_in_w, "R(W) subset W", all(mapped), mapped)

    # Orbit behavior of the three-dimensional affine fixed-space layer when the
    # input constant is projected onto W. This is a well-defined auxiliary map;
    # output RC terms are not invented.
    for start in vals:
        o = start
        seen = {}
        for k in range(60):
            if o in seen:
                print("projected orbit start", f"{start:x}", "preperiod", seen[o], "period", k - seen[o])
                break
            seen[o] = k
            o = psi(o)
        else:
            print("projected orbit start", f"{start:x}", "no repeat in 60")


if __name__ == "__main__":
    main()
