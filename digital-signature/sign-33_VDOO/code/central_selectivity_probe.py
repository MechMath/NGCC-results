#!/usr/bin/env python3
"""Probe the rank of central VDOO polar directions.

This is an exploratory finite-field experiment.  It constructs the supported
central coefficient pattern with identity outer transforms, then computes the
rank of L_b for standard directions.  It is not a key-generation distribution
test.
"""

from __future__ import annotations

import argparse
import random


class GF256:
    def __init__(self):
        self.exp = [0] * 510
        self.log = [0] * 256
        x = 1
        for i in range(255):
            self.exp[i] = x
            self.log[x] = i
            x <<= 1
            if x & 0x100:
                x ^= 0x11B
        for i in range(255, 510):
            self.exp[i] = self.exp[i - 255]

    def mul(self, a: int, b: int) -> int:
        if not a or not b:
            return 0
        return self.exp[self.log[a] + self.log[b]]

    def inv(self, a: int) -> int:
        if not a:
            raise ZeroDivisionError
        return self.exp[255 - self.log[a]]


def central_dims(v: int, d: int, o1: int, o2: int) -> int:
    return v + d + o1 + o2


def allowed(groups: tuple[int, int, int, int], out: int, i: int, j: int) -> bool:
    v, d, o1, o2 = groups
    n = v + d + o1 + o2
    if i > j:
        i, j = j, i
    if out < d:
        boundary = v + out
        return j < boundary or (i < boundary and j == boundary)
    if out < d + o1:
        j_o1 = out - d
        boundary = v + d
        return j < boundary or (i < boundary and j == boundary + j_o1)
    j_o2 = out - d - o1
    boundary = v + d + o1
    return j < boundary or (i < boundary and j == boundary + j_o2)


def sparse_central(
    groups: tuple[int, int, int, int], rng: random.Random, field: GF256
) -> list[dict[tuple[int, int], int]]:
    v, d, o1, o2 = groups
    n = central_dims(v, d, o1, o2)
    m = d + o1 + o2
    ans: list[dict[tuple[int, int], int]] = []
    for out in range(m):
        coeffs: dict[tuple[int, int], int] = {}
        for i in range(n):
            for j in range(i, n):
                if allowed(groups, out, i, j):
                    value = rng.randrange(1, 256)
                    if value:
                        coeffs[i, j] = value
        ans.append(coeffs)
    return ans


def polar_matrix(
    forms: list[dict[tuple[int, int], int]],
    n: int,
    b: list[int],
    field: GF256,
) -> list[list[int]]:
    """Return the n-by-m matrix x -> P'(x,b), in characteristic two."""
    m = len(forms)
    mat = [[0] * m for _ in range(n)]
    for out, coeffs in enumerate(forms):
        for (i, j), c in coeffs.items():
            if i == j:
                continue
            mat[j][out] ^= field.mul(c, b[i])
            mat[i][out] ^= field.mul(c, b[j])
    return mat


def rank_mod2ish(mat: list[list[int]], field: GF256) -> int:
    """Gaussian rank over GF(256), using multiplication by inverse entries."""
    a = [row[:] for row in mat]
    rows = len(a)
    cols = len(a[0]) if rows else 0
    rank = 0
    for col in range(cols):
        pivot = next((r for r in range(rank, rows) if a[r][col]), None)
        if pivot is None:
            continue
        a[rank], a[pivot] = a[pivot], a[rank]
        inv = field.inv(a[rank][col])
        a[rank] = [field.mul(x, inv) for x in a[rank]]
        for r in range(rows):
            if r != rank and a[r][col]:
                factor = a[r][col]
                a[r] = [x ^ field.mul(factor, y) for x, y in zip(a[r], a[rank])]
        rank += 1
        if rank == rows:
            break
    return rank


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--v", type=int, required=True)
    p.add_argument("--d", type=int, required=True)
    p.add_argument("--o1", type=int, required=True)
    p.add_argument("--o2", type=int, required=True)
    p.add_argument("--seed", type=int, default=1)
    args = p.parse_args()
    groups = (args.v, args.d, args.o1, args.o2)
    n = central_dims(*groups)
    field = GF256()
    forms = sparse_central(groups, random.Random(args.seed), field)
    print(f"n={n} m={sum(groups[1:])} r={args.o2}")
    for index in range(n):
        b = [0] * n
        b[index] = 1
        rank = rank_mod2ish(polar_matrix(forms, n, b, field), field)
        if index < args.v:
            layer = "V"
        elif index < args.v + args.d:
            layer = "D"
        elif index < args.v + args.d + args.o1:
            layer = "O1"
        else:
            layer = "O2"
        print(index, layer, rank)


if __name__ == "__main__":
    main()
