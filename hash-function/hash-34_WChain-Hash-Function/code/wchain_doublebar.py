#!/usr/bin/env python3
"""Minimal one-block WChain model for the rendered hash-34 equation (22)."""

from __future__ import annotations

import math
from functools import lru_cache


MASK64 = (1 << 64) - 1
PI = [0, 7, 5, 3, 1, 8, 6, 4, 2]
ROT_D = (0, 1, 10, 20, 25, 32, 41, 46, 50)

ROWS_L = [
    ((0, 5), (1, 22), (2, 3), (3, 28), (7, 27)),
    ((1, 39), (2, 59), (3, 45), (4, 3), (8, 9)),
    ((2, 54), (3, 6), (4, 20), (5, 8), (0, 48)),
    ((3, 0), (4, 57), (5, 55), (6, 46), (1, 28)),
    ((4, 61), (5, 38), (6, 0), (7, 44), (2, 52)),
    ((5, 29), (6, 10), (7, 37), (8, 19), (3, 7)),
    ((6, 56), (7, 5), (8, 50), (0, 27), (4, 13)),
    ((7, 40), (8, 10), (0, 11), (1, 54), (5, 14)),
    ((8, 3), (0, 38), (1, 36), (2, 17), (6, 13)),
]

DELTA_R = (11, 21, 19, 21, 43, 5, 3, 10, 5)
ROWS_R = [
    tuple((j, (a + DELTA_R[i]) % 64) for j, a in ROWS_L[i])
    for i in range(9)
]


def rotl64(x: int, n: int) -> int:
    n %= 64
    return ((x << n) | (x >> (64 - n))) & MASK64


def sbox9_u64(a: list[int]) -> list[int]:
    """Equation (22), including both the inner and outer rendered bars."""
    return [
        a[i] ^ (a[(i + 1) % 9] | ((~a[(i + 2) % 9]) & MASK64))
        for i in range(9)
    ]


def sbox9_scalar(x: int) -> int:
    out = 0
    for i in range(9):
        a_i = (x >> i) & 1
        a_i1 = (x >> ((i + 1) % 9)) & 1
        a_i2 = (x >> ((i + 2) % 9)) & 1
        b_i = a_i ^ (~(~a_i1 & a_i2) & 1)
        out |= b_i << i
    return out


def linear_table(a: list[int], rows) -> list[int]:
    return [
        _xor_all(rotl64(a[j], r) for j, r in rows[i])
        for i in range(9)
    ]


def _xor_all(xs) -> int:
    out = 0
    for x in xs:
        out ^= x
    return out


@lru_cache(maxsize=None)
def pi16_word(j: int) -> int:
    # Fractional hexadecimal digits of pi, beginning 243F...
    from mpmath import mp

    mp.dps = 130
    n = int((mp.pi - 3) * (16 ** 96))
    return (n >> (16 * (24 - j))) & 0xFFFF


def round_v1(x: list[int], j: int) -> list[int]:
    c = pi16_word(j)
    x = [x[i] ^ rotl64(c, i) for i in range(9)]
    x = sbox9_u64(x)
    x = [x[PI.index(i)] for i in range(9)]
    return linear_table(x, ROWS_L)


def round_v2(left: list[int], right: list[int], j: int) -> tuple[list[int], list[int]]:
    c = pi16_word(j)
    left = [left[i] ^ rotl64(c, i) for i in range(9)]
    right = [right[i] ^ rotl64(c, i + 9) for i in range(9)]
    left = sbox9_u64(left)
    right = sbox9_u64(right)
    left = [left[PI.index(i)] for i in range(9)]
    right = [right[PI.index(i)] for i in range(9)]

    for li, ri in ((0, 0), (1, 3), (3, 1), (4, 4), (6, 6)):
        left[li], right[ri] = right[ri], left[li]

    return linear_table(left, ROWS_L), linear_table(right, ROWS_R)


def mef_v1(a: list[int]) -> list[int]:
    return sbox9_u64([rotl64(a[i], ROT_D[i]) for i in range(9)])


def expansion_v1(block: int) -> tuple[list[list[int]], list[int]]:
    lanes = [(block >> (1152 - 64 * (i + 1))) & MASK64 for i in range(18)]
    e = [lanes[:9], lanes[9:]]
    for _ in range(2, 19):
        e.append([a ^ b for a, b in zip(mef_v1(e[-1]), e[-2])])
    return e[:19], lanes


def expansion_v2(block: int) -> tuple[list[tuple[list[int], list[int]]], list[int]]:
    lanes = [(block >> (2304 - 64 * (i + 1))) & MASK64 for i in range(36)]
    e = [(lanes[:9], lanes[9:18]), (lanes[18:27], lanes[27:36])]
    for _ in range(2, 25):
        pl, pr = e[-1]
        ql, qr = e[-2]
        ml, mr = mef_v1(pl), mef_v1(pr)
        e.append(([a ^ b for a, b in zip(ml, ql)],
                  [a ^ b for a, b in zip(mr, qr)]))
    return e[:25], lanes


def cf_v1(v: list[int], block: int) -> list[int]:
    e, _ = expansion_v1(block)
    x = v[:]
    for j in range(1, 19):
        x = round_v1([a ^ b for a, b in zip(x, e[j - 1])], j)
    return [a ^ b ^ c for a, b, c in zip(x, e[18], v)]


def cf_v2(v: tuple[list[int], list[int]], block: int):
    e, _ = expansion_v2(block)
    xl, xr = v[0][:], v[1][:]
    for j in range(1, 25):
        pl, pr = e[j - 1]
        xl, xr = round_v2(
            [a ^ b for a, b in zip(xl, pl)],
            [a ^ b for a, b in zip(xr, pr)],
            j,
        )
    el, er = e[24]
    return (
        [a ^ b ^ c for a, b, c in zip(xl, el, v[0])],
        [a ^ b ^ c for a, b, c in zip(xr, er, v[1])],
    )


def one_block_digest(version: int, first_padded_byte: int) -> bytes:
    if version == 1:
        block = first_padded_byte << (1152 - 8)
        h1 = cf_v1([0] * 9, block)
        final = cf_v1(h1, block)
        return b"".join(x.to_bytes(8, "big") for x in final[:8])
    if version == 2:
        block = first_padded_byte << (2304 - 8)
        h1 = cf_v2(([0] * 9, [0] * 9), block)
        final = cf_v2(h1, block)
        return b"".join(x.to_bytes(8, "big") for x in final[0] + final[1][:7])
    raise ValueError(version)


def validate_sbox() -> None:
    values = [sbox9_scalar(x) for x in range(512)]
    assert len(set(values)) == 512
    max_ddt = 0
    for dx in range(1, 512):
        counts = [0] * 512
        for x in range(512):
            counts[sbox9_scalar(x) ^ sbox9_scalar(x ^ dx)] += 1
        max_ddt = max(max_ddt, max(counts))
    # Double Walsh-Hadamard transform of M[x][S(x)].
    matrix = [[0] * 512 for _ in range(512)]
    for x, y in enumerate(values):
        matrix[x][y] = 1
    for row in matrix:
        step = 1
        while step < 512:
            for start in range(0, 512, 2 * step):
                for j in range(start, start + step):
                    u, v = row[j], row[j + step]
                    row[j], row[j + step] = u + v, u - v
            step *= 2
    for step in (1, 2, 4, 8, 16, 32, 64, 128, 256):
        for start in range(0, 512, 2 * step):
            for j in range(start, start + step):
                for b in range(512):
                    u, v = matrix[j][b], matrix[j + step][b]
                    matrix[j][b], matrix[j + step][b] = u + v, u - v
    max_lat = max(abs(matrix[a][b]) for a in range(1, 512) for b in range(512))
    print(f"sbox bijective: 512/512; DDTmax={max_ddt}; LATmax_nonzero={max_lat}")


if __name__ == "__main__":
    validate_sbox()
    for version in (1, 2):
        print(f"V{version} M=1:", one_block_digest(version, 0xC0).hex())
        print(f"V{version} M=0:", one_block_digest(version, 0x40).hex())
