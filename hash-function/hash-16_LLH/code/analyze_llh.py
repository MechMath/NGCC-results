#!/usr/bin/env python3
"""Finite checks of the LLH S6/S24 round components.

This is exploratory code.  Cryptographic evidence is submitted separately
through crypto_run.
"""

from itertools import combinations, product


P = [4, 9, 18, 23, 8, 1, 22, 15, 12, 17, 6, 3,
     20, 5, 10, 19, 0, 21, 14, 11, 16, 13, 2, 7]


def ror6(x, r):
    return ((x >> r) | (x << (6 - r))) & 63


def s6(x):
    return (x ^ ror6(x, 2) ^ (ror6(x, 1) & ror6(x, 3)) ^ 0x1B) & 63


def permute24(x):
    y = 0
    for old, new in enumerate(P):
        y |= ((x >> old) & 1) << new
    return y


def d4(x):
    """Multiply the 6 row bits by D=J4+I4, rows in bits 0..3."""
    assert x < 16
    total = x.bit_count() & 1
    return x ^ (15 if total else 0)


def s24(x):
    y = 0
    for c in range(4):
        v = 0
        for r in range(6):
            v |= ((x >> (4 * r + c)) & 1) << r
        sv = s6(v)
        for r in range(6):
            y |= ((sv >> r) & 1) << (4 * r + c)
    y = permute24(y)
    z = 0
    for r in range(6):
        z |= d4((y >> (4 * r)) & 15) << (4 * r)
    return z


def nonlinear_layer(x):
    return s24(x)


def differential_table(f, n):
    out = [[0] * (1 << n) for _ in range(1 << n)]
    for x in range(1 << n):
        fx = f(x)
        for dx in range(1 << n):
            out[dx][fx ^ f(x ^ dx)] += 1
    return out


def rank(vectors, n):
    basis = [0] * n
    for x in vectors:
        while x:
            i = x.bit_length() - 1
            if basis[i]:
                x ^= basis[i]
            else:
                basis[i] = x
                break
    return sum(v != 0 for v in basis)


def walsh(f):
    t = [0] * (1 << 12)
    for a in range(64):
        for b in range(64):
            for x in range(64):
                parity = ((a & x) ^ (b & f(x))).bit_count() & 1
                t[a << 6 | b] += -1 if parity else 1
    return t


def all_subspaces(n):
    """Yield distinct linear subspaces of GF(2)^n as frozensets."""
    seen = set()
    for r in range(n + 1):
        for pivots in combinations(range(n), r):
            pivot_set = set(pivots)
            free = [
                [c for c in range(p, n) if c not in pivot_set]
                for p in pivots
            ]
            choices = product(*(range(1 << len(f)) for f in free))
            for assignment in choices:
                gens = []
                for p, fs, a in zip(pivots, free, assignment):
                    g = 1 << p
                    for j, c in enumerate(fs):
                        if (a >> j) & 1:
                            g |= 1 << c
                    gens.append(g)
                sp = {0}
                for x in gens:
                    sp |= {y ^ x for y in tuple(sp)}
                sp = frozenset(sp)
                if sp not in seen:
                    seen.add(sp)
                    yield sp


def summarize_s6():
    table = [s6(x) for x in range(64)]
    print("S6 permutation", len(set(table)) == 64)
    for bit in range(6):
        vals = [(s6(x) >> bit) & 1 for x in range(64)]
        for i in range(6):
            for x in range(64):
                if x & (1 << i):
                    vals[x] ^= vals[x ^ (1 << i)]
        degree = max((x.bit_count() for x, v in enumerate(vals) if v),
                     default=0)
        print("component degree", bit, degree)
    dt = differential_table(s6, 6)
    max_ddt = max(max(row[1:]) for row in dt[1:])
    print("DDT max", max_ddt, "uniform", (max_ddt - 1) * 2)
    print("fixed", [x for x in range(64) if s6(x) == x])
    print("zero differential equalities", [
        (d, n) for d, row in enumerate(dt) if d and row[0]
        for n in [row[0]]
    ])
    w = walsh(s6)
    print("Walsh max nonzero masks", max(abs(w[a << 6 | b])
          for a in range(64) for b in range(64) if a or b))
    # Algebraic normal forms, retaining monomial coefficients.
    anfs = []
    for bit in range(6):
        vals = [(s6(x) >> bit) & 1 for x in range(64)]
        for i in range(6):
            for x in range(64):
                if x & (1 << i):
                    vals[x] ^= vals[x ^ (1 << i)]
        anfs.append({x: v for x, v in enumerate(vals) if v})
    print("ANF per output bit",
          [[hex(m) for m in coeff] for coeff in anfs])
    zero_quadratic_subspaces = []
    for u in all_subspaces(6):
        d = rank(u, 6)
        if d <= 4:
            if all(
                sum(anf.get(x, 0) for x in u) % 2 == 0
                for anf in anfs
            ):
                zero_quadratic_subspaces.append((d, tuple(sorted(u))))
    maxd = max((d for d, _ in zero_quadratic_subspaces), default=0)
    print("largest affine-linear S6 direction dimension", maxd,
          [u for d, u in zero_quadratic_subspaces if d == maxd][:3])
    # Find affine subspaces whose S6 image is affine (under exact addition).
    for n in range(1, 7):
        found = 0
        examples = []
        for u in all_subspaces(6):
            if rank(u, 6) != n:
                continue
            uu = tuple(u)
            for a in range(64):
                vals = {s6(a ^ x) for x in uu}
                if len(vals) != len(uu):
                    continue
                b = next(iter(vals))
                v = frozenset(x ^ b for x in vals)
                if rank(v, 6) != n:
                    continue
                if len(v) != len(uu):
                    continue
                # Affinity means the set equals b+V for a linear V.
                found += 1
                if len(examples) < 3:
                    examples.append((a, tuple(uu), b, tuple(sorted(v))))
        print("affine->affine representations by input dimension", n, found,
              "examples", examples)


def rate_slice_collisions():
    # Fix capacity bits of every S6 input to zero and vary only rows 0,1.
    mask = 0
    for c in range(4):
        mask |= 0b11 << c
    images = {}
    for x in range(256):
        xx = sum(((x >> (4 * r + c)) & 1) << (4 * r + c)
                 for r in range(2) for c in range(4))
        images.setdefault(nonlinear_layer(xx), []).append(xx)
    cols = [v for v in images.values() if len(v) > 1]
    print("rate-only per-slice S24->D collisions", len(cols),
          "largest", max(map(len, cols), default=0))
    if cols:
        print("example", cols[0])


def rate_slice_collision_any_capacity(seed=0):
    """Search a capacity setting where one slice merges two rate inputs."""
    import random

    rng = random.Random(seed)
    rate_positions = [4 * r + c for r in range(2) for c in range(4)]
    cap_positions = [4 * r + c for r in range(2, 6) for c in range(4)]
    for trial in range(10000):
        capacity = rng.getrandbits(24)
        capacity &= sum(1 << p for p in cap_positions)
        seen = {}
        for m in range(256):
            x = capacity
            for j, p in enumerate(rate_positions):
                x |= ((m >> j) & 1) << p
            y = nonlinear_layer(x)
            if y in seen and seen[y] != x:
                print("rate-only collision", {
                    "trial": trial, "capacity": capacity, "x": x,
                    "m0": seen[y], "m1": x, "output": y,
                })
                return seen[y], x, y
            seen[y] = x
    print("no rate-only collision in capacity search")
    return None


def kernel_and_quotient():
    vectors = [0xF << (4 * r) for r in range(6)]
    print("D kernel dimension", rank(vectors, 24))
    # Parity of each four-bit row is a full invariant of D.
    for x in range(1 << 18):
        pass


if __name__ == "__main__":
    summarize_s6()
    rate_slice_collisions()
    rate_slice_collision_any_capacity()
    kernel_and_quotient()
