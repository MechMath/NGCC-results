#!/usr/bin/env python3
"""Reproduce the conditional SMM sizing for the VDOO MinRank interface."""

from math import comb


def bit_length_interval(value):
    return value.bit_length() - 1, value.bit_length()


cases = [
    ("VDOO-128", 16, 40, 98, 137, 70, 65, 2),
    ("VDOO-256", 256, 68, 233, 300, 95, 94, 9),
    ("VDOO-512", 256, 175, 281, 455, 195, 195, 58),
]

for name, q, r, k, n, m, mp, b in cases:
    columns = comb(b + k - 1, b) * comb(mp, r)
    rows = sum(
        (-1) ** (i + 1)
        * comb(mp, r + i)
        * comb(n + i - 1, i)
        * comb(k + b - i - 1, b - i)
        for i in range(1, b + 1)
    )
    field_ops = 3 * columns * columns * (r + 1) * k
    q_field_ops = q * field_ops
    dense_entries = (
        n
        * comb(mp, r + 1)
        * comb(b + k - 2, b - 1)
        * columns
    )
    print(
        name,
        {
            "full_rank_branch": rows >= columns - 1,
            "M_columns": columns,
            "R_rows": rows,
            "field_ops": field_ops,
            "field_ops_log2_interval": bit_length_interval(field_ops),
            "q_field_ops": q_field_ops,
            "q_field_ops_log2_interval": bit_length_interval(q_field_ops),
            "dense_entries": dense_entries,
            "dense_entries_bit_length": dense_entries.bit_length(),
        },
    )
