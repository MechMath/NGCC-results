#!/usr/bin/env python3
"""Exact linear checks relevant to one-round capacity confinement."""

from __future__ import annotations

import json

from chime_reference import State, lam


N = 1536
RATE = 512


def basis_state(j: int) -> State:
    vals = [0] * 6
    vals[j // 256] = 1 << (255 - j % 256)
    return State(*vals)


def rank(vectors: list[int]) -> int:
    pivots: dict[int, int] = {}
    for value in vectors:
        row = value
        while row:
            pivot = row.bit_length() - 1
            if pivot not in pivots:
                pivots[pivot] = row
                break
            row ^= pivots[pivot]
    return len(pivots)


def main() -> None:
    prefix = [1 << (N - 1 - j) for j in range(RATE)]
    capacity_image = [lam(basis_state(j)).to_bits_int() for j in range(RATE, N)]
    combined_rank = rank(prefix + capacity_image)
    print(json.dumps({
        "prefix_dimension": RATE,
        "capacity_dimension": N - RATE,
        "lambda_capacity_image_dimension": rank(capacity_image),
        "span_prefix_plus_lambda_capacity_dimension": combined_rank,
        "intersection_dimension_by_rank_formula": (
            RATE + (N - RATE) - combined_rank
        ),
        "intersection_is_zero": combined_rank == N,
    }, indent=2))


if __name__ == "__main__":
    main()
