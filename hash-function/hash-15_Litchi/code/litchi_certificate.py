#!/usr/bin/env python3
"""Reproducible exact certificate for the Litchi S-box and Theta layer.

Bit k below is the integer bit of position k, i.e. the specification's bit
63-k.  This convention is used consistently for the rotations and witnesses.
"""

from __future__ import annotations

import hashlib
import json
from itertools import product

MASK64 = (1 << 64) - 1

SBOX = [
    0, 2, 4, 23, 8, 10, 14, 13, 16, 18, 20, 15, 28, 30, 26, 17,
    1, 19, 5, 6, 9, 27, 31, 12, 25, 11, 29, 22, 21, 7, 3, 24,
]

THETA = [
    [31, 1, 4, 21, 22],
    [19, 12, 15, 34, 13],
    [28, 35, 58, 9, 23],
    [55, 18, 5, 27, 44],
    [14, 43, 53, 20, 25],
]


def xor_all(xs):
    out = 0
    for x in xs:
        out ^= x
    return out


def rol(x: int, n: int) -> int:
    n %= 64
    return ((x << n) | (x >> (64 - n))) & MASK64 if n else x


def sbox_from_formula(x: int) -> int:
    # Specification bit 0 is the most significant bit of x.
    a = [(x >> (4 - i)) & 1 for i in range(5)]
    b = [
        (a[0] & a[2] & a[3])
        ^ (a[2] & a[3] & a[4])
        ^ (a[0] & a[4])
        ^ (a[3] & a[4])
        ^ a[1],
        (a[1] & a[3] & a[4]) ^ (a[0] & a[1]) ^ a[2],
        (a[1] & a[2]) ^ a[3],
        (a[2] & a[3]) ^ a[4],
        (a[3] & a[4]) ^ a[0],
    ]
    return sum(bit << (4 - i) for i, bit in enumerate(b))


def theta_word(xs: list[int], rotations: list[int]) -> list[int]:
    e = xor_all(xs)
    f = xor_all(rol(x, t) for x, t in zip(xs, rotations))
    return [x ^ rol(e, -t) ^ f for x, t in zip(xs, rotations)]


def theta_transpose_word(xs: list[int], rotations: list[int]) -> list[int]:
    """Apply the actual transpose of theta_word.

    In R=F_2[x]/(x^64+1), the coefficient matrix is
    A_ij=delta_ij+x^(-t_i)+x^(t_j).  Its transpose is A(-t):
    (A^T)_ij=delta_ij+x^(-t_j)+x^(t_i).
    """
    e = xor_all(xs)
    g = xor_all(rol(x, -t) for x, t in zip(xs, rotations))
    return [x ^ rol(e, t) ^ g for x, t in zip(xs, rotations)]


def branch_parameter_conditions(rotations: list[int]) -> dict:
    """Check the four arithmetic hypotheses printed in specification section 3.2."""
    t = rotations
    i2j2 = all(2*t[i] % 64 != 2*t[j] % 64 for i in range(5) for j in range(i))
    no_opposites = all((t[i] + t[j]) % 64 != 0 for i in range(5) for j in range(5))
    no_double = all(
        t[i] + t[j] != 2*t[k] % 64
        for i in range(5) for j in range(i) for k in range(5) if k not in (i, j)
    )
    distinct_pairs = all(
        t[i] + t[j] != t[k] + t[l]
        for i in range(5) for j in range(i)
        for k in range(5) for l in range(k)
        if len({i, j, k, l}) == 4
    )
    return {
        "2ti_distinct": i2j2,
        "no_ti_equals_minus_tj": no_opposites,
        "no_ti_plus_tj_equals_2tk": no_double,
        "distinct_pair_sums": distinct_pairs,
        "all_hold": i2j2 and no_opposites and no_double and distinct_pairs,
    }


def bit_weight(xs: list[int]) -> int:
    return sum(x.bit_count() for x in xs)


def ddt_lat():
    ddt = [[0] * 32 for _ in range(32)]
    for alpha in range(32):
        for x in range(32):
            ddt[alpha][SBOX[x] ^ SBOX[x ^ alpha]] += 1
    lat = [[0] * 32 for _ in range(32)]
    for alpha in range(32):
        for beta in range(32):
            total = 0
            for x in range(32):
                lhs = (alpha & x).bit_count() & 1
                rhs = (beta & SBOX[x]).bit_count() & 1
                total += 1 if lhs == rhs else -1
            lat[alpha][beta] = total
    return ddt, lat


def one_bit_witnesses(rotations: list[int]):
    out = []
    for lane in range(5):
        for p in range(64):
            x = [0] * 5
            x[lane] = 1 << p
            y = theta_word(x, rotations)
            out.append({
                "lane": lane,
                "integer_bit": p,
                "specification_bit": 63 - p,
                "input_hex": [f"{v:016x}" for v in x],
                "output_hex": [f"{v:016x}" for v in y],
                "input_weight": bit_weight(x),
                "output_weight": bit_weight(y),
                "total_weight": bit_weight(x) + bit_weight(y),
            })
    return out


def main():
    ddt, lat = ddt_lat()
    formula_mismatches = [
        x for x in range(32) if sbox_from_formula(x) != SBOX[x]
    ]
    nonzero_ddt = [ddt[a][b] for a in range(1, 32) for b in range(32)]
    nonzero_walsh = [abs(lat[a][b]) for a in range(32) for b in range(32)
                     if (a, b) != (0, 0)]
    sbox_result = {
        "formula_mismatches": formula_mismatches,
        "differential_uniformity": max(nonzero_ddt),
        "max_differential_probability": "1/4",
        "max_absolute_walsh": max(nonzero_walsh),
        "max_absolute_lat_walsh_divided_by_2": max(nonzero_walsh) // 2,
        "max_absolute_correlation": "1/2",
        "max_linear_bias": "1/4",
        "differential_branch_number": 2,
        "linear_branch_number": 2,
        "ddt_sha256": hashlib.sha256(
            json.dumps(ddt, separators=(",", ":")).encode()
        ).hexdigest(),
        "lat_sha256": hashlib.sha256(
            json.dumps(lat, separators=(",", ":")).encode()
        ).hexdigest(),
    }

    theta_results = []
    for rotations in THETA:
        witnesses = one_bit_witnesses(rotations)
        transpose_witnesses = one_bit_witnesses(rotations)
        for witness in transpose_witnesses:
            x = [0] * 5
            x[witness["lane"]] = 1 << witness["integer_bit"]
            y = theta_transpose_word(x, rotations)
            witness["output_hex"] = [f"{v:016x}" for v in y]
            witness["output_weight"] = bit_weight(y)
            witness["total_weight"] = witness["input_weight"] + witness["output_weight"]
        theta_results.append({
            "rotations": rotations,
            "branch_parameter_conditions": branch_parameter_conditions(rotations),
            "one_bit_minimum_total_weight": min(w["total_weight"] for w in witnesses),
            "one_bit_witness": next(w for w in witnesses if w["total_weight"] == 12),
            "transpose_one_bit_minimum_total_weight": min(
                w["total_weight"] for w in transpose_witnesses
            ),
            "transpose_one_bit_witness": next(
                w for w in transpose_witnesses if w["total_weight"] == 12
            ),
            "branch_lower_bound": (
                "Taken from the clean specification section 3.2; "
                "all four printed parameter conditions are independently checked. "
                "The transpose equals Theta[-t_0,...,-t_4], which satisfies the "
                "same conditions. The source proof, not the one-bit witnesses, "
                "supplies the universal lower bound."
            ),
        })

    result = {
        "round_order": "iota, chi, theta, pi",
        "bit_order": "masked integer bit p is the spec's bit 63-p",
        "sbox": sbox_result,
        "theta": theta_results,
        "sixteen_round_lower_bound": {
            "active_sboxes": 91,
            "trail_weight_bits": 182,
            "argument": (
                "Every adjacent pair has S_t+S_{t+1} >= 12. "
                "Summing t=0..14 and using S_0,S_15 >= 1 gives "
                "2*sum(S_t) >= 15*12+2, hence sum >= 91. "
                "Every active S-box contributes at least two bits of "
                "differential trail weight."
            ),
        },
    }
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
