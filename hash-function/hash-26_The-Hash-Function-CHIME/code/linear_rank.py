#!/usr/bin/env python3
"""Compute exact GF(2) rank and kernel of CHIME's lambda map."""

from __future__ import annotations

import json

from chime_reference import State, lam


N = 1536


def state_from_column(j: int) -> State:
    vals = [0] * 6
    vals[j // 256] = 1 << (255 - j % 256)
    return State(*vals)


def gf2_basis() -> tuple[int, list[int], list[int]]:
    """Return rank, row echelon basis, and pivot columns of lambda."""
    row_basis = [0] * N
    pivots: list[int] = []
    for j in range(N):
        v = lam(state_from_column(j)).bits()
        row = int(v, 2)
        for pivot in pivots:
            if (row >> pivot) & 1:
                row ^= row_basis[pivot]
        if row:
            pivot = row.bit_length() - 1
            row_basis[pivot] = row
            pivots.append(pivot)
            pivots.sort(reverse=True)
    return len(pivots), row_basis, sorted(pivots)


def main() -> None:
    rank, row_basis, pivots = gf2_basis()
    print(json.dumps({
        "ambient_dimension": N,
        "rank": rank,
        "nullity": N - rank,
        "pivot_count": len(pivots),
        "full_rank": rank == N,
    }, indent=2))


if __name__ == "__main__":
    main()
