#!/usr/bin/env python3
"""Exact GF(2) analysis of the Thunder theta correction kernel."""

from __future__ import annotations

import itertools
import json
from collections import Counter

import thunder as t

N = 1600


def apply_correction(value: int) -> int:
    state = t.state_int_to_lanes(value)
    return value ^ t.lanes_to_state_int(t.theta(state))


def row_reduce(map_function) -> tuple[dict[int, int], list[int]]:
    basis: dict[int, int] = {}
    kernel = []
    for input_bit in range(N):
        image = map_function(1 << input_bit)
        dependency = 1 << input_bit
        while image:
            pivot = (image & -image).bit_length() - 1
            if pivot not in basis:
                basis[pivot] = image
                basis[pivot + N] = dependency
                break
            image ^= basis[pivot]
            dependency ^= basis[pivot + N]
        if not image:
            if map_function(dependency):
                raise AssertionError("constructed vector is not in the kernel")
            kernel.append(dependency)
    return {pivot: basis[pivot] for pivot in basis if pivot < N}, kernel


def rank(rows: list[int]) -> int:
    basis: dict[int, int] = {}
    for row in rows:
        while row:
            pivot = row.bit_length() - 1
            if pivot not in basis:
                basis[pivot] = row
                break
            row ^= basis[pivot]
    return len(basis)


def cap_restriction_rank(kernel_basis: list[int], nc: int) -> int:
    # Columns are kernel basis vectors; rows are their 64*nc capacity
    # coordinates.  The nullity is dim(K intersect {capacity difference = 0}).
    rows = []
    for bit in range(64 * nc):
        row = 0
        for column, vector in enumerate(kernel_basis):
            if (vector >> bit) & 1:
                row |= 1 << column
        if row:
            rows.append(row)
    return rank(rows)


def weight_statistics(vectors: list[int], max_full_enumeration_dimension: int = 22) -> dict:
    result = {
        "kernel_dimension": len(vectors),
        "basis_weights": [v.bit_count() for v in vectors],
    }
    if len(vectors) <= max_full_enumeration_dimension:
        distribution: Counter[int] = Counter()
        minimum = N + 1
        minimizers = []
        for mask in range(1, 1 << len(vectors)):
            value = 0
            bits = mask
            while bits:
                bit = (bits & -bits).bit_length() - 1
                value ^= vectors[bit]
                bits &= bits - 1
            weight = value.bit_count()
            distribution[weight] += 1
            if weight < minimum:
                minimum = weight
                minimizers = [value]
            elif weight == minimum and len(minimizers) < 32:
                minimizers.append(value)
        result.update(
            {
                "enumerated": True,
                "minimum_weight": minimum,
                "weight_distribution": dict(sorted(distribution.items())),
                "minimizer_masks": minimizers,
            }
        )
    else:
        result["enumerated"] = False
    return result


def main() -> None:
    basis, vectors = row_reduce(apply_correction)
    profiles = {}
    for name, nc in (("Thunder-512", 9), ("Thunder-768", 13), ("Thunder-1024", 17)):
        restriction_rank = cap_restriction_rank(vectors, nc)
        profiles[name] = {
            "capacity_bits": 64 * nc,
            "restriction_rank": restriction_rank,
            "intersection_dimension": len(vectors) - restriction_rank,
        }
    print(
        json.dumps(
            {
                "rank": len(basis),
                "pivots": sorted(basis),
                **weight_statistics(vectors),
                "profiles": profiles,
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
