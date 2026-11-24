#!/usr/bin/env python3
"""Eliminate additive S-box-cycle invariants from one Thunder-p round."""

import random

from thunder_fixedspace import RC, linear, pos


CYCLES = [
    [0],
    [1, 12, 16, 6, 8, 3, 4, 17, 2, 24],
    [5, 21, 18, 26, 9, 13, 20, 22, 10, 11],
    [7, 28, 19, 14, 25],
    [15, 29, 23, 30, 27],
    [31],
]
CYCLE_OF = {}
for i, cycle in enumerate(CYCLES):
    for value in cycle:
        CYCLE_OF[value] = i


def slice_value(x, a, z):
    return sum(((x >> pos(a, y, z)) & 1) << y for y in range(5))


def signature(x):
    """Parity counts of the six S-box cycle classes over all 320 slices."""
    out = 0
    for a in range(5):
        for z in range(64):
            out ^= 1 << CYCLE_OF[slice_value(x, a, z)]
    return out


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


def find_basis_witnesses(rnd, rng):
    witnesses = []
    differences = []
    for _ in range(10000):
        x = rng.getrandbits(1600)
        d = signature(x) ^ signature(linear(x ^ RC[rnd]))
        if d and d not in differences:
            cbasis = {}
            for v in differences + [d]:
                while v:
                    p = v.bit_length() - 1
                    if p in cbasis:
                        v ^= cbasis[p]
                    else:
                        cbasis[p] = v
                        break
            if len(cbasis) > rank(differences):
                witnesses.append(x)
                differences.append(d)
            # Differences provably lie in the even-weight subspace: f=all ones
            # gives the identically zero XOR sum over all 320 slices. Hence
            # rank five suffices to separate every nonconstant label.
            if len(witnesses) == 5:
                return witnesses, differences
    raise RuntimeError("failed to find full-rank witnesses")


def main():
    rng = random.Random(0x7A1D3)
    for rnd in range(12):
        witnesses, differences = find_basis_witnesses(rnd, rng)
        assert rank(differences) == 5
        print("round", rnd, "rank", rank(differences))
        for j, (x, d) in enumerate(zip(witnesses, differences)):
            print("  witness", j, "x_hex", f"{x:0400x}", "sigdiff", f"{d:02x}")

        # For each nonconstant 6-bit cycle-function label f, at least one
        # witness must violate f-invariance because the sigdiff vectors span
        # the even-weight subspace. Labels 0 and 63 give identically zero sums
        # over the 320 S-boxes and are excluded as trivial.
        for f in range(1, 63):
            assert any(((f & d).bit_count() & 1) for d in differences)


if __name__ == "__main__":
    main()
