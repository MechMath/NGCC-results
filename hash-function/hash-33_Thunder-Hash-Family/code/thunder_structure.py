#!/usr/bin/env python3
"""Exact bit-sliced model of the pinned Thunder-p round."""

from __future__ import annotations

MASK = (1 << 64) - 1

TAU = (
    (45, 40, 34, 48, 6),
    (33, 52, 5, 30, 18),
    (13, 19, 0, 61, 49),
    (1, 47, 2, 8, 17),
    (27, 9, 37, 38, 43),
)

# r, s, t_y, u from Table 4, excluding the common r,s,u values after a check.
TY = (41, 50, 6, 10, 27)
ROUND_CONSTANTS = (
    0x0000000000000001,
    0x0000000000000003,
    0x000000000000000A,
    0x0000000000000088,
    0x0000000000008081,
    0x0000000000008002,
    0x0000000000000009,
    0x0000000000000083,
    0x000000000000800A,
    0x0000000000000089,
    0x0000000000008083,
    0x000000000000800B,
)


def rotr(x: int, n: int) -> int:
    n %= 64
    return ((x >> n) | (x << (64 - n))) & MASK


def theta(d: list[list[int]]) -> list[list[int]]:
    p = [0] * 5
    q = [0] * 5
    for x in range(5):
        for y in range(5):
            p[x] ^= d[x][y]
            q[x] ^= rotr(d[x][y], TY[y])
    e = [p[x] ^ rotr(p[(x - 1) % 5], 1) for x in range(5)]
    f = [q[(x + 1) % 5] ^ rotr(q[(x - 2) % 5], 36) for x in range(5)]
    out = [[0] * 5 for _ in range(5)]
    for x in range(5):
        for y in range(5):
            out[x][y] = d[x][y] ^ rotr(e[x], 26) ^ rotr(f[x], 26 + TY[y])
    return out


def pi(d: list[list[int]]) -> list[list[int]]:
    out = [[0] * 5 for _ in range(5)]
    for x in range(5):
        for y in range(5):
            out[(2 * x + 3 * y + 2) % 5][y] = d[x][y]
    return out


def psi_lane(words: list[int]) -> list[int]:
    out = [0] * 5
    for y in range(5):
        out[y] = (
            words[(y + 3) % 5]
            ^ (((~words[(y + 1) % 5]) & MASK) & words[(y + 2) % 5] & ((~words[(y + 4) % 5]) & MASK))
        )
    return out


def psi(d: list[list[int]]) -> list[list[int]]:
    out = [[0] * 5 for _ in range(5)]
    for x in range(5):
        column = psi_lane([d[x][y] for y in range(5)])
        for y in range(5):
            out[x][y] = column[y]
    return out


def round_fn(d: list[list[int]], rc: int) -> list[list[int]]:
    d = [row[:] for row in d]
    d[0][0] ^= rc
    d = [[rotr(d[x][y], TAU[x][y]) for y in range(5)] for x in range(5)]
    return psi(pi(theta(d)))


def inverse_psi_lane(words: list[int]) -> list[int]:
    # psi acts independently on each bit. Invert its 32-point truth table.
    table: dict[int, int] = {}
    for x in range(32):
        bits = [(x >> i) & 1 for i in range(5)]
        y_bits = []
        for y in range(5):
            y_bits.append(
                bits[(y + 3) % 5]
                ^ ((1 ^ bits[(y + 1) % 5]) & bits[(y + 2) % 5] & (1 ^ bits[(y + 4) % 5]))
            )
        table[sum(v << i for i, v in enumerate(y_bits))] = x
    assert len(table) == 32
    out = [0] * 5
    for bit in range(64):
        encoded = sum(((words[i] >> bit) & 1) << i for i in range(5))
        recovered = table[encoded]
        for i in range(5):
            out[i] |= ((recovered >> i) & 1) << bit
    return out


if __name__ == "__main__":
    from itertools import product

    lane_maps = set()
    for x, y in product(range(5), repeat=2):
        lane_maps.add(((2 * x + 3 * y + 2) % 5, y))
    assert len(lane_maps) == 25
    for i in range(1 << 10):
        words = [(i * 0x9E3779B97F4A7C15 + j * 0xD1B54A32D192ED03) & MASK for j in range(5)]
        assert inverse_psi_lane(psi_lane(words)) == words
    print("pi is a lane permutation; sampled psi inversion is exact")
