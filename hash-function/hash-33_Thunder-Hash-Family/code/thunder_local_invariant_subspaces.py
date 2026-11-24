#!/usr/bin/env python3
"""Enumerate all GF(2) subspaces of the pinned Thunder 5-bit S-box."""

from itertools import combinations


def sbox(a):
    x = [(a >> i) & 1 for i in range(5)]
    return sum(
        (
            x[(y + 3) % 5]
            ^ ((1 ^ x[(y + 1) % 5]) & x[(y + 2) % 5] & (1 ^ x[(y + 4) % 5]))
        )
        << y
        for y in range(5)
    )


def main():
    assert len({sbox(x) for x in range(32)}) == 32
    subspaces = {frozenset({0})}
    for dimension in range(1, 6):
        found = set()
        for basis in combinations(range(1, 32), dimension):
            values = {0}
            for b in basis:
                values |= {v ^ b for v in list(values)}
            if len(values) == 1 << dimension:
                found.add(frozenset(values))
        assert len(found) == {
            1: 31,
            2: 155,
            3: 155,
            4: 31,
            5: 1,
        }[dimension]
        subspaces |= found
    assert len(subspaces) == 374

    invariant = []
    for A in subspaces:
        if all(sbox(x) in A for x in A):
            invariant.append(A)
    invariant.sort(key=lambda A: (len(A), sorted(A)))
    print("subspaces", len(subspaces))
    print("invariant", len(invariant))
    for A in invariant:
        print("dim", len(A).bit_length() - 1, "members", sorted(A))
    assert {len(A) for A in invariant} == {1, 2, 32}


if __name__ == "__main__":
    main()
