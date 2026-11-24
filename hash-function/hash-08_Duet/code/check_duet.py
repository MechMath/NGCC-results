#!/usr/bin/env python3
"""Exact finite checks of the pinned Duet specification.

Input: hash-08-spec.pdf with SHA-256
6a846acc98114368059b96e42925877e06a4cdd423e36143ee274e2679dfbf9f.

This script checks the specified S-box (Table 1 versus Table 2 under the
stated MSB convention), M15, the sigma word permutations, and the Mix-Lane
circulants. The f-1920 M30 branch-number check is exhaustive and is run by
branch30.c; this script checks its rank over GF(2).
"""

from __future__ import annotations

import hashlib
import itertools
import json
from pathlib import Path


SPEC_SHA256 = "6a846acc98114368059b96e42925877e06a4cdd423e36143ee274e2679dfbf9f"

SBOX = [
    0x1A, 0x09, 0x10, 0x17, 0x07, 0x08, 0x15, 0x0E, 0x19, 0x1F, 0x1E, 0x0C,
    0x1B, 0x01, 0x04, 0x0A, 0x05, 0x13, 0x0D, 0x0F, 0x16, 0x1C, 0x06, 0x18,
    0x11, 0x12, 0x14, 0x03, 0x1D, 0x02, 0x00, 0x0B,
]

M15_ROWS = """
1 0 0 1 1 1 0 1 1 0 0 0 0 1 0
0 1 0 0 1 1 1 0 1 1 0 0 0 0 1
1 0 1 0 0 1 1 1 0 1 1 0 0 0 0
0 1 0 1 0 0 1 1 1 0 1 1 0 0 0
0 0 1 0 1 0 0 1 1 1 0 1 1 0 0
0 0 0 1 0 1 0 0 1 1 1 0 1 1 0
0 0 0 0 1 0 1 0 0 1 1 1 0 1 1
1 0 0 0 0 1 0 1 0 0 1 1 1 0 1
1 1 0 0 0 0 1 0 1 0 0 1 1 1 0
0 1 1 0 0 0 0 1 0 1 0 0 1 1 1
1 0 1 1 0 0 0 0 1 0 1 0 0 1 1
1 1 0 1 1 0 0 0 0 1 0 1 0 0 1
1 1 1 0 1 1 0 0 0 0 1 0 1 0 0
0 1 1 1 0 1 1 0 0 0 0 1 0 1 0
0 0 1 1 1 0 1 1 0 0 0 0 1 0 1
"""

M30_FIRST = [
    1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1,
    1, 1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0,
]

SIGMAS = {
    384: [3, 0, 5, 1, 4, 2],
    1088: [9, 2, 15, 0, 6, 12, 4, 16, 1, 10, 7, 14, 3, 11, 5, 13, 8],
    768: [8, 2, 11, 0, 5, 9, 3, 10, 1, 7, 4, 6],
}


def sbox_circuit(u: int) -> int:
    x = [(u >> (4 - i)) & 1 for i in range(5)]
    t = [0] * 52
    t[0] = x[3] & x[4]
    t[1] = x[2] & x[4]
    t[2] = x[2] & x[3]
    t[3] = x[1] & x[4]
    t[4] = x[1] & x[2]
    t[5] = x[0] & x[1]
    t[6] = x[4] ^ x[2]
    t[7] = x[0] ^ t[0]
    t[8] = t[1] ^ t[2]
    t[9] = t[3] ^ t[4]
    t[10] = t[5] ^ t[6]
    t[11] = t[7] ^ t[8]
    t[12] = t[9] ^ t[10]
    t[13] = t[11] ^ t[12]
    t[14] = t[13] ^ 1  # y0
    t[15] = x[1] & x[3]
    t[16] = x[0] & x[2]
    t[17] = x[3] ^ x[2]
    t[18] = x[0] ^ t[1]
    t[19] = t[2] ^ t[15]
    t[20] = t[4] ^ t[16]
    t[21] = t[17] ^ t[18]
    t[22] = t[19] ^ t[20]
    t[23] = t[21] ^ t[22]
    t[24] = t[23] ^ 1  # y1
    t[25] = x[0] & x[4]
    t[26] = x[2] ^ x[0]
    t[27] = t[0] ^ t[1]
    t[28] = t[3] ^ t[15]
    t[29] = t[4] ^ t[25]
    t[30] = t[16] ^ t[5]
    t[31] = t[26] ^ t[27]
    t[32] = t[28] ^ t[29]
    t[33] = t[30] ^ t[31]
    t[34] = t[32] ^ t[33]  # y2
    t[35] = x[0] & x[3]
    t[36] = x[4] ^ x[3]
    t[37] = x[1] ^ x[0]
    t[38] = t[4] ^ t[35]
    t[39] = t[16] ^ t[5]
    t[40] = t[36] ^ t[37]
    t[41] = t[38] ^ t[39]
    t[42] = t[40] ^ t[41]
    t[43] = t[42] ^ 1  # y3
    t[44] = x[4] ^ x[2]
    t[45] = x[1] ^ x[0]
    t[46] = t[3] ^ t[15]
    t[47] = t[4] ^ t[25]
    t[48] = t[5] ^ t[44]
    t[49] = t[45] ^ t[46]
    t[50] = t[47] ^ t[48]
    t[51] = t[49] ^ t[50]  # y4
    y = [t[14], t[24], t[34], t[43], t[51]]
    # Table 1's convention: y0 is the MSB and y4 is the LSB.
    return sum(bit << (4 - i) for i, bit in enumerate(y))


def gf2_rank(rows: list[list[int]]) -> int:
    a = [row[:] for row in rows]
    rank = 0
    for col in range(len(a[0])):
        pivot = next((i for i in range(rank, len(a)) if a[i][col]), None)
        if pivot is None:
            continue
        a[rank], a[pivot] = a[pivot], a[rank]
        for i in range(len(a)):
            if i != rank and a[i][col]:
                a[i] = [x ^ y for x, y in zip(a[i], a[rank])]
        rank += 1
    return rank


def gf2_kernel(rows: list[list[int]]) -> list[list[int]]:
    a = [row[:] for row in rows]
    m, n = len(a), len(a[0])
    pivots: list[int] = []
    rank = 0
    for col in range(n):
        pivot = next((i for i in range(rank, m) if a[i][col]), None)
        if pivot is None:
            continue
        a[rank], a[pivot] = a[pivot], a[rank]
        for i in range(m):
            if i != rank and a[i][col]:
                a[i] = [x ^ y for x, y in zip(a[i], a[rank])]
        pivots.append(col)
        rank += 1
    free = [col for col in range(n) if col not in pivots]
    basis = []
    for f in free:
        x = [0] * n
        x[f] = 1
        for row, pivot in enumerate(pivots):
            x[pivot] = a[row][f]
        basis.append(x)
    return basis


def mul_matrix(a: list[list[int]], x: list[int]) -> list[int]:
    return [sum(row[j] & x[j] for j in range(len(x))) & 1 for row in a]


def branch_number_exhaustive(a: list[list[int]]) -> tuple[int, list[int], list[int]]:
    n = len(a)
    best, bx, by = n * 2 + 1, [], []
    for mask in range(1, 1 << n):
        x = [(mask >> i) & 1 for i in range(n)]
        y = mul_matrix(a, x)
        weight = sum(x) + sum(y)
        if weight < best:
            best, bx, by = weight, x, y
    return best, bx, by


def m15_sc_ms_slice(x: int) -> int:
    """One 15-bit slice of SC then MS, with no AC or ML.

    This is only a reduced component: AC is an affine bit injection into one
    64-bit lane and ML mixes the 64 bit slices, so this map is not a
    restriction of either full permutation.
    """
    y = 0
    for j in range(3):
        u = 0
        for i in range(5):
            u = (u << 1) | ((x >> (5 * j + i)) & 1)
        s = SBOX[u]
        for i in range(5):
            y |= ((s >> (4 - i)) & 1) << (5 * j + i)
    return sum(bit << i for i, bit in enumerate(mul_matrix(M15_ROWS_MATRIX, [(y >> j) & 1 for j in range(15)])))


def make_m30() -> list[list[int]]:
    rows = []
    for i in range(30):
        row = [0] * 30
        for j, bit in enumerate(M30_FIRST):
            row[(j + i) % 30] = bit
        rows.append(row)
    return rows


def poly_mod(a: int, b: int) -> int:
    while a and a.bit_length() >= b.bit_length():
        a ^= b << (a.bit_length() - b.bit_length())
    return a


def poly_gcd(a: int, b: int) -> int:
    while b:
        a, b = b, poly_mod(a, b)
    return a


def rol64(x: int, r: int) -> int:
    r %= 64
    if r == 0:
        return x
    return ((x << r) | (x >> (64 - r))) & ((1 << 64) - 1)


def mix_lane(x: int, t: int) -> int:
    return rol64(x, t) ^ rol64(x, t + 21) ^ rol64(x, t + 43)


def mix_lane_branch(t: int) -> tuple[int, int, int]:
    """Exhaustively cover all inputs whose weight could make branch < 4."""
    candidates = [1 << i for i in range(64)]
    candidates += [(1 << i) | (1 << j) for i in range(64) for j in range(i)]
    best = 5
    best_x = best_y = 0
    for x in candidates:
        y = mix_lane(x, t)
        weight = x.bit_count() + y.bit_count()
        if weight < best:
            best, best_x, best_y = weight, x, y
    return best, best_x, best_y


def anf_coefficients(values: list[int]) -> list[int]:
    """Return the truth-table coefficients of f in the mobius transform."""
    a = values[:]
    n = len(a).bit_length() - 1
    for i in range(n):
        for x in range(1 << n):
            if x & (1 << i):
                a[x] ^= a[x ^ (1 << i)]
    return a


def anf_degree(values: list[int]) -> int:
    coeff = anf_coefficients(values)
    return max(mask.bit_count() for mask, bit in enumerate(coeff) if bit)


def main() -> None:
    root = Path(__file__).resolve().parent
    pdf = root / "hash-08-spec.pdf"
    digest = hashlib.sha256(pdf.read_bytes()).hexdigest()
    if digest != SPEC_SHA256:
        raise SystemExit(f"spec digest {digest} != {SPEC_SHA256}")

    circuit = [sbox_circuit(u) for u in range(32)]
    sbox_bijective = len(set(SBOX)) == 32
    ddt = [[0] * 32 for _ in range(32)]
    for a in range(32):
        for x in range(32):
            ddt[a][SBOX[x] ^ SBOX[x ^ a]] += 1
    lat = [[0] * 32 for _ in range(32)]
    for a in range(32):
        for b in range(32):
            lat[a][b] = sum(
                1 if (a & x).bit_count() % 2 == (b & SBOX[x]).bit_count() % 2 else -1
                for x in range(32)
            )
    max_ddt = max(max(row[1:]) for row in ddt)
    max_lat = max(abs(lat[a][b]) for a in range(32) for b in range(1, 32))
    fixed = [u for u in range(32) if SBOX[u] == u]
    single_bit_self_diff = [
        a for a in (1, 2, 4, 8, 16) if any(SBOX[x] ^ SBOX[x ^ a] == a for x in range(32))
    ]
    zero_difference = [a for a in range(1, 32) if all(SBOX[x] ^ SBOX[x ^ a] == 0 for x in range(32))]
    degrees = [
        anf_degree([(SBOX[u] >> bit) & 1 for u in range(32)])
        for bit in range(5)
    ]

    m15 = [[int(x) for x in line.split()] for line in M15_ROWS.splitlines() if line.strip()]
    global M15_ROWS_MATRIX
    M15_ROWS_MATRIX = m15
    m30 = make_m30()
    m15_branch, m15_x, m15_y = branch_number_exhaustive(m15)
    slice_fixed = [x for x in range(1 << 15) if m15_sc_ms_slice(x) == x]

    # ML(x) = x xor ROL_21(x) xor ROL_43(x).  The kernel dimension is
    # deg(gcd(1+z^21+z^43, z^64-1)), with z^64-1 coefficients in GF(2).
    mod_poly = (1 << 64) | 1
    ml_poly = 1 | (1 << 21) | (1 << 43)
    ml_gcd = poly_gcd(mod_poly, ml_poly)
    ml_branch = {str(t): mix_lane_branch(t)[0] for t in range(30)}

    outputs = {
        "spec_sha256": digest,
        "sbox": {
            "table_matches_circuit_y0_msb": circuit == SBOX,
            "bijective": sbox_bijective,
            "anf_degrees_y0_to_y4": degrees,
            "max_anf_degree": max(degrees),
            "differential_uniformity_count": max_ddt,
            "max_differential_probability": f"{max_ddt}/32",
            "max_absolute_lat_entry": max_lat,
            "max_absolute_linear_correlation": f"{max_lat}/32",
            "fixed_points": fixed,
            "single_bit_self_differentials": single_bit_self_diff,
            "zero_differentials": zero_difference,
        },
        "M15": {
            "rank_gf2": gf2_rank(m15),
            "kernel_dimension": len(gf2_kernel(m15)),
            "branch_number_exhaustive_over_nonzero_x": m15_branch,
            "branch_witness_x": "".join(map(str, m15_x)),
            "branch_witness_Mx": "".join(map(str, m15_y)),
            "reduced_SC_MS_slice_fixed_points_hex": [f"{x:04x}" for x in slice_fixed],
            "reduced_SC_MS_slice_scope": (
                "Exhaustive over all 2^15 values of one 15-bit slice; "
                "omits AC and ML, so it is not a full-round fixed point."
            ),
        },
        "M30": {
            "rank_gf2": gf2_rank(m30),
            "kernel_dimension": len(gf2_kernel(m30)),
            "branch_number": "see branch30.c exhaustive run",
        },
        "sigma": {
            str(width): {
                "order": order,
                "length": len(order),
                "is_permutation": sorted(order) == list(range(len(order))),
            }
            for width, order in SIGMAS.items()
        },
        "MixLane": {
            "polynomial": "1 + x^21 + x^43",
            "modulus": "x^64 + 1 over GF(2)",
            "gcd_hex": hex(ml_gcd),
            "kernel_dimension": ml_gcd.bit_length() - 1,
            "bijective": ml_gcd == 1,
            "branch_number_each_t_0_to_29": ml_branch,
        },
        "limitations": [
            "M30 branch number is certified only by the exhaustive branch30.c run.",
            "This script checks the concrete round components, not key/permutation security.",
            "No full-state fixed point search or nonlinear reduced-round search is asserted.",
        ],
    }
    text = json.dumps(outputs, indent=2, sort_keys=True)
    print(text)
    (root / "duet_exact_checks.json").write_text(text + "\n")


if __name__ == "__main__":
    main()
