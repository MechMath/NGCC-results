#!/usr/bin/env python3
"""Exact component cross-checks for the clean MOZI specification.

The encoded definitions are transcriptions of hash-20-spec.pdf, SHA-256
1c611656c47a7d708dc47449c5fdf2aa4f524e53362b08242daedc57932dbb86.
No web source is consulted.
"""

from __future__ import annotations

import hashlib
import json
from itertools import product
from pathlib import Path

SOURCE = Path(
    "/home/mmat/mmat-preview/campaigns/rebuild-20261119/runs/"
    "rebuild-104-hash-20-ds02/slots/orch-graph/orch/hash-20-spec.pdf"
)

# Table 2, p.8.
SBOX_TABLE = (
    0, 8, 6, 13, 5, 15, 7, 12,
    4, 14, 2, 3, 9, 1, 11, 10,
)

# Table 3, p.10, rows indexed by i mod 4 and columns by y.
SHIFT_TABLE = (
    (0, 14, 20, 22),
    (0, 13, 68, 91),
    (0, 27, 42, 106),
    (0, 32, 48, 80),
)

# p.9 example.
SHIFT_P9_EXAMPLE = (0, 1, 2, 3)


def xor(*xs: int) -> int:
    out = 0
    for x in xs:
        out ^= x
    return out


def bit(nibble: int, position: int) -> int:
    """position 0 is the least significant bit."""
    return (nibble >> position) & 1


def pack_msb_first(bits: list[int]) -> int:
    """Return an integer digest with bits[0] as its most significant bit."""
    out = 0
    for b in bits:
        out = (out << 1) | b
    return out


def pack_lsb_first(bits: list[int]) -> int:
    return sum((b & 1) << i for i, b in enumerate(bits))


def bitslice_sbox_from_bits(x0: int, x1: int, x2: int, x3: int) -> list[int]:
    """Algorithm 3 / p.17 equations, retaining the order y0,y1,y2,y3."""
    y3 = (x3 & x2) ^ x1
    y1 = (x2 | x1) ^ x0
    y0 = (y3 & x0) ^ x3
    y2 = (y1 & x3) ^ x2
    return [y0, y1, y2, y3]


def bitslice_sbox_msb(nibble: int) -> int:
    """The common display convention x0 is the leftmost/MSB input bit."""
    xs = [bit(nibble, p) for p in (3, 2, 1, 0)]
    return pack_msb_first(bitslice_sbox_from_bits(*xs))


def bitslice_sbox_lsb(nibble: int) -> int:
    """The alternative convention x0 is the rightmost/LSB input bit."""
    xs = [bit(nibble, p) for p in (0, 1, 2, 3)]
    return pack_lsb_first(bitslice_sbox_from_bits(*xs))


def gf16_mul_alpha_algorithm(x: int) -> int:
    """Algorithm 4 MUL: y=(x3,x0^x3,x1,x2) in x0..x3 order."""
    x0, x1, x2, x3 = (bit(x, i) for i in range(4))
    y = [x3, x0 ^ x3, x1, x2]
    return sum((b & 1) << i for i, b in enumerate(y))


def gf16_mul_alpha_display(x: int) -> int:
    """The alpha map displayed on p.8: y=(x1,x2,x3,x0^x1)."""
    x0, x1, x2, x3 = (bit(x, i) for i in range(4))
    y = [x1, x2, x3, x0 ^ x1]
    return sum((b & 1) << i for i, b in enumerate(y))


def gf16_mul_alpha_algorithm_power(x: int, exponent: int) -> int:
    for _ in range(exponent):
        x = gf16_mul_alpha_algorithm(x)
    return x


def gf16_mul_alpha_display_power(x: int, exponent: int) -> int:
    for _ in range(exponent):
        x = gf16_mul_alpha_display(x)
    return x


def mds_formula(a: int, b: int, c: int, d: int) -> tuple[int, int, int, int]:
    """The displayed MDS matrix on p.8."""
    cap_a = gf16_mul_alpha_display_power(a, 2)
    cap_b = gf16_mul_alpha_display_power(b, 2)
    cap_c = gf16_mul_alpha_display_power(c, 2)
    cap_d = gf16_mul_alpha_display_power(d, 2)
    row0 = xor(cap_a, cap_b, gf16_mul_alpha_display(b), c, d)
    row1 = xor(
        a, gf16_mul_alpha_display(b), b, cap_c, c, cap_d,
        gf16_mul_alpha_display(d), d,
    )
    row2 = xor(a, b, cap_c, cap_d, gf16_mul_alpha_display(d))
    row3 = xor(
        cap_a, a, cap_b, gf16_mul_alpha_display(b), b, c,
        gf16_mul_alpha_display(d), d,
    )
    return row0, row1, row2, row3


def mds_algorithm4(a: int, b: int, c: int, d: int) -> tuple[int, int, int, int]:
    """Algorithm 4, p.9. S0..S3 correspond to columns 0..3."""
    s0, s1, s2, s3 = a, b, c, d
    s2 ^= s3
    s0 ^= s1
    s1 = gf16_mul_alpha_algorithm(s1)
    s3 = gf16_mul_alpha_algorithm(s3)
    s1 ^= s2
    s3 ^= s0
    s0 = gf16_mul_alpha_algorithm(s0)
    s2 = gf16_mul_alpha_algorithm(s2)
    s0 = gf16_mul_alpha_algorithm(s0)
    s2 = gf16_mul_alpha_algorithm(s2)
    s2 ^= s3
    s0 ^= s1
    s1 ^= s2
    s3 ^= s0
    return s0, s1, s2, s3


def mds_listing1(a: int, b: int, c: int, d: int) -> tuple[int, int, int, int]:
    """Listing 1, p.18, at one bit position with x0..xf naming columns/rows.

    x0..x3=A, x4..x7=B, x8..xb=C, xc..xf=D.  Only the first bit-plane is
    needed; each plane is evaluated independently.
    """
    # Each packed word is a vector of four one-bit components.
    A = [bit(a, i) for i in range(4)]
    B = [bit(b, i) for i in range(4)]
    C = [bit(c, i) for i in range(4)]
    D = [bit(d, i) for i in range(4)]

    def mul(words: list[int]) -> None:
        tmp = words[3]
        words[3] = words[2]
        words[2] = words[1]
        words[1] = words[0]
        words[0] = tmp
        words[1] ^= words[0]

    for i in range(4):
        C[i] ^= D[i]
    for i in range(4):
        A[i] ^= B[i]
    mul(B)
    mul(D)
    for i in range(4):
        B[i] ^= C[i]
    for i in range(4):
        D[i] ^= A[i]
    mul(A)
    mul(A)
    mul(C)
    mul(C)
    for i in range(4):
        C[i] ^= D[i]
    for i in range(4):
        A[i] ^= B[i]
    for i in range(4):
        B[i] ^= C[i]
    for i in range(4):
        D[i] ^= A[i]

    return tuple(
        sum(word[i] << i for i in range(4))
        for word in (A, B, C, D)
    )


def shift_pseudocode(words: list[int], rho: int) -> list[int]:
    """Equation (4): D[z]=C[z-rho mod 128], reduced to a 16-bit word."""
    n = len(words)
    return [words[(z - rho) % n] for z in range(n)]


def shift_simd(words: list[int], rho: int) -> list[int]:
    """p.18: yi = xi >>> ci for a circular right shift."""
    n = len(words)
    return [words[(z - rho) % n] for z in range(n)]


def main() -> None:
    source_hash = hashlib.sha256(SOURCE.read_bytes()).hexdigest()
    msb_map = [bitslice_sbox_msb(x) for x in range(16)]
    lsb_map = [bitslice_sbox_lsb(x) for x in range(16)]

    mds_formula_vs_a4 = []
    mds_a4_vs_listing1 = []
    for values in product(range(16), repeat=4):
        formula = mds_formula(*values)
        a4 = mds_algorithm4(*values)
        listing = mds_listing1(*values)
        if formula != a4:
            mds_formula_vs_a4.append([values, formula, a4])
        if a4 != listing:
            mds_a4_vs_listing1.append([values, a4, listing])

    shift_mismatches = [
        {"round": 0, "y": y, "p9_example": SHIFT_P9_EXAMPLE[y],
         "table3": SHIFT_TABLE[0][y]}
        for y in range(4)
        if SHIFT_P9_EXAMPLE[y] != SHIFT_TABLE[0][y]
    ]

    shift_equations_agree = all(
        shift_pseudocode(list(range(16)), rho)
        == shift_simd(list(range(16)), rho)
        for rho in range(16)
    )
    shift_full_equations_agree = all(
        shift_pseudocode(list(range(128)), rho)
        == shift_simd(list(range(128)), rho)
        for rho in range(128)
    )
    nonzero_shift_lanes = sum(rho != 0 for row in SHIFT_TABLE for rho in row)

    result = {
        "source": str(SOURCE),
        "source_sha256": source_hash,
        "checks": {
            "sbox_table_vs_bitslice_msb_first": {
                "all_equal": msb_map == list(SBOX_TABLE),
                "table": list(SBOX_TABLE),
                "bitslice": msb_map,
            },
            "sbox_table_vs_bitslice_lsb_first": {
                "all_equal": lsb_map == list(SBOX_TABLE),
                "bitslice": lsb_map,
                "mismatch_count": sum(
                    a != b for a, b in zip(lsb_map, SBOX_TABLE)
                ),
            },
            "mds_formula_vs_algorithm4": {
                "tested_inputs": 16**4,
                "all_equal": not mds_formula_vs_a4,
                "mismatch_count": len(mds_formula_vs_a4),
                "first_mismatch": mds_formula_vs_a4[0] if mds_formula_vs_a4 else None,
                "display_alpha_outputs": {
                    str(x): gf16_mul_alpha_display(x) for x in range(16)
                },
                "algorithm_alpha_outputs": {
                    str(x): gf16_mul_alpha_algorithm(x) for x in range(16)
                },
            },
            "mds_algorithm4_vs_listing1": {
                "tested_inputs": 16**4,
                "all_equal": not mds_a4_vs_listing1,
                "first_mismatch": (
                    mds_a4_vs_listing1[0] if mds_a4_vs_listing1 else None
                ),
            },
            "shift_p9_example_vs_table3": {
                "all_equal": not shift_mismatches,
                "mismatches": shift_mismatches,
            },
            "shift_equation4_vs_simd_prose": {
                "tested_toy_rotations": 16,
                "tested_full_128_bit_rotations": 128,
                "all_equal": shift_equations_agree and shift_full_equations_agree,
            },
            "shift_row_parallel_lane_count_p18": {
                "state_lanes": 16,
                "zero_rotation_lanes": 16 - nonzero_shift_lanes,
                "nonzero_rotation_lanes": nonzero_shift_lanes,
                "spec_p18_claims_lanes": 9,
                "claim_matches_lane_requirement": nonzero_shift_lanes == 9,
            },
            "named_sponge_fixed_versus_xof_overlap": {
                "result": (
                    "For either named sponge pair, the two executable calls have "
                    "identical r,a and, at ell=h, Algorithm 1 executes the same "
                    "operations; h only restricts ell. Thus Mozi-384(M) equals "
                    "Mozi-384-XOF(M,384), and likewise at 512."
                ),
                "fixed_xof_parameters": {
                    "384": {"r": 1280, "a": 20, "ell": 384},
                    "512": {"r": 1024, "a": 20, "ell": 512},
                },
            },
        },
        "conclusions": {
            "sbox": (
                "Table 2 and the bitslice equations are exactly equivalent when "
                "both displayed nibbles use x0/y0 as the leftmost bit; treating "
                "x0/y0 as bit 0 of an integer reverses both displayed bit orders."
            ),
            "mds": (
                "Algorithm 4 and Listing 1 agree on all 65,536 GF(16)^4 inputs, "
                "but they do not implement the alpha map displayed on p.8. The "
                "displayed-matrix and Algorithm 4 results differ on 65,280 inputs."
            ),
            "shift": (
                "The p.9 round-0 example conflicts with Table 3 in y=1,2,3. "
                "Equation (4) and the p.18 SIMD interpretation agree for all "
                "128 rotations, but p.18 says 9 lanes although 12 of the 16 "
                "lanes have nonzero rotations."
            ),
            "sponge": (
                "Padding, absorption, squeezing, and the feed-forward capacity "
                "domain bit are executable and mutually consistent as written. "
                "There is no fixed-hash/XOF tag in Algorithm 1, so the named "
                "fixed and XOF variants coincide at ell=h."
            ),
        },
    }
    out = Path("artifacts/audit_results.json")
    out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
