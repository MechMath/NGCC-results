#!/usr/bin/env python3
from itertools import combinations


def psi(x):
    a = [(x >> y) & 1 for y in range(5)]
    b = [a[(y + 3) % 5] ^ ((a[(y + 1) % 5] ^ 1) & a[(y + 2) % 5] & (a[(y + 4) % 5] ^ 1)) for y in range(5)]
    return sum(v << y for y, v in enumerate(b))


def affine_on_plane(c, u, v):
    for i, j in ((1, 0), (0, 1), (1, 1)):
        if psi(c ^ (i * u) ^ (j * v)) != psi(c) ^ (i * (psi(c) ^ psi(c ^ u))) ^ (j * (psi(c) ^ psi(c ^ v))):
            return False
    return True


directions = [(u, v) for u, v in combinations(range(1, 32), 2) if (u ^ v) != 0]
print("direction spaces", len(directions))
count = 0
for u, v in directions:
    cosets = [c for c in range(32) if affine_on_plane(c, u, v)]
    if cosets:
        print(hex(u), hex(v), "cosets", [hex(c) for c in cosets])
        count += len(cosets)
print("planes", count)
