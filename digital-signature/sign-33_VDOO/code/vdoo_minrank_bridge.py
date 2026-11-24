#!/usr/bin/env python3
"""Exact arithmetic for the VDOO rectangular-MinRank bridge.

This script does not solve a MinRank instance.  It records:
* the supported VDOO dimensions and the number of post-hyperplane matrices;
* the conditional Support Minors Model (SMM) column count;
* the characteristic-two-corrected SMM rank-model threshold and its
  field-multiplication estimate.

The formulas are from Beullens, "Improved Cryptanalysis of UOV and
Rainbow", EUROCRYPT 2021, Section 2.3 (with the rank expression credited
there to Bardet et al.).
"""

from __future__ import annotations

import json
from math import comb, log2


PARAMETERS = [
    # name, q, v, d, o1, o2, m
    ("VDOO-128", 16, 67, 16, 14, 40, 70),
    ("VDOO-256", 256, 205, 10, 17, 68, 95),
    ("VDOO-512", 256, 260, 10, 10, 175, 195),
]


def monomial_columns(b: int, k: int, r: int, m_prime: int) -> int:
    """Number M(b,1) of degree-(b,1) y,c monomials."""
    return comb(b + k - 1, b) * comb(m_prime, r)


def generic_minor_rank(
    b: int, k: int, n: int, m_prime: int, r: int
) -> int:
    """Bardet et al. naive-rank expression used by the SMM analysis."""
    return sum(
        (-1) ** (i + 1)
        * comb(m_prime, r + i)
        * comb(n + i - 1, i)
        * comb(k + b - i - 1, b - i)
        for i in range(1, b + 1)
    )


def first_full_rank_degree_char_two(
    k: int, n: int, m_prime: int, r: int
) -> tuple[int, int, int]:
    """Return (b_min, R_b, M_b) for the corrected rank model.

    In characteristic two, Beullens removes one polar row before applying
    the generic rank model.  The callers pass n-1 to generic_minor_rank.
    At b = r+1, the paper's full-rank branch applies unconditionally.
    """
    for b in range(1, r + 2):
        rank_expr = generic_minor_rank(b, k, n - 1, m_prime, r)
        columns = monomial_columns(b, k, r, m_prime)
        if b == r + 1 or rank_expr >= columns - 1:
            return b, rank_expr, columns
    raise AssertionError("unreachable")


def evaluate_tuple(name: str, q: int, v: int, d: int, o1: int, o2: int, m: int):
    n = v + m
    r = o2
    k = n - r + 1

    candidates = []
    for m_prime in range(r + 1, m + 1):
        b, rank_expr, columns = first_full_rank_degree_char_two(
            k, n, m_prime, r
        )
        # The Wiedemann cost stated in Beullens Section 2.3.
        field_multiplications = 3 * columns * columns * (r + 1) * k
        candidates.append(
            {
                "m_prime": m_prime,
                "b_min": b,
                "M_b": columns,
                "M_b_bits": columns.bit_length(),
                "rank_expression": rank_expr,
                "rank_expression_ge_M_b_minus_1": rank_expr >= columns - 1,
                "smm_field_multiplications": field_multiplications,
                "smm_field_multiplications_log2": log2(field_multiplications),
            }
        )

    best = min(candidates, key=lambda row: row["smm_field_multiplications"])

    # The model's maximum equation weight is (r+1)k.  In characteristic
    # two one row was removed; the corrected number of bilinear equation
    # rows before multiplying by y-monomials is (n-1)*C(m_prime,r+1).
    equation_rows = (
        (n - 1)
        * comb(best["m_prime"], r + 1)
        * comb(best["b_min"] + k - 2, best["b_min"] - 1)
    )
    dense_matrix_entries = equation_rows * best["M_b"]

    return {
        "name": name,
        "q": q,
        "v": v,
        "d": d,
        "o1": o1,
        "o2": o2,
        "n": n,
        "m": m,
        "rectangular_matrices_after_fixing_o2_minus_1_coefficients": k,
        "target_rank": r,
        "best_conditional_smm": best,
        "maximum_equation_weight": (r + 1) * k,
        "macaulay_equation_rows": equation_rows,
        "macaulay_equation_rows_bits": equation_rows.bit_length(),
        "dense_Macaulay_entries": dense_matrix_entries,
        "dense_Macaulay_entries_bits": dense_matrix_entries.bit_length(),
        "one_guess_with_additional_q_factor_field_multiplications": (
            q * best["smm_field_multiplications"]
        ),
    }


def main() -> None:
    rows = [evaluate_tuple(*params) for params in PARAMETERS]
    assert [row["rectangular_matrices_after_fixing_o2_minus_1_coefficients"] for row in rows] == [
        98,
        233,
        281,
    ]
    print(json.dumps({"parameters": rows}, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
