#!/usr/bin/env python3
"""Independent Laurus hash-14 reference checks from the allowlisted specification.

This is an audit note, not crypto_run evidence.  It implements:
  * the Section 2.3/3.2/5.2 pi maps and their 25-lane equivalence;
  * the 16-round permutation from Sections 2.3 and 5.1;
  * the first squeeze chunk for the final padding block 1 || 0^511.

Source identity:
  https://cdn.jsdelivr.net/gh/ngcc-dev/ngcc-harness@dc66c6cb3c06e75bdea0048e21fa4e13c63f00af/hash-14/hash-14-spec.pdf
  sha256 63190edaf6bd2b85c93f21f49412567cfcb0c8330063c9124d19cd64cd91b141
"""

from __future__ import annotations

RC = (
    0xB7E151628AED2A6A,
    0xAF82A3CD15DAD4D7,
    0x9F4546922BB529AD,
    0xFECA8C2C576AD359,
    0x3DD51950AED526B1,
    0x7BAA32A15DAA4D62,
    0xF7546542BB549AC4,
    0x2EE8CB8D76A9B58B,
    0x5DD1971AED536B16,
    0xBBA32E35DAA6D62C,
    0xB7065D63B54D2C5B,
    0xAE4CBBCF6A9AD8B5,
    0x9CD97696D5353169,
    0xF9F2EC25AA6AE2D1,
    0x33A5D94354D545A1,
    0x674BB286A9AA8B42,
)

THETA = (
    (31, 1, 4, 21, 22),
    (19, 12, 15, 34, 13),
    (28, 35, 58, 9, 23),
    (55, 18, 5, 27, 44),
    (14, 43, 53, 20, 25),
)

# Source lane linear index -> destination coordinate, from M=[[4,4],[1,3]].
PI_FORWARD = (
    (0, 0),
    (4, 3),
    (3, 1),
    (2, 4),
    (1, 2),
    (4, 1),
    (3, 4),
    (2, 2),
    (1, 0),
    (0, 3),
    (3, 2),
    (2, 0),
    (1, 3),
    (0, 1),
    (4, 4),
    (2, 3),
    (1, 1),
    (0, 4),
    (4, 2),
    (3, 0),
    (1, 4),
    (0, 2),
    (4, 0),
    (3, 3),
    (2, 1),
)


def bits(value: int, width: int) -> list[int]:
    """MSB-left bit array of an ordinary width-bit integer."""
    return [(value >> (width - 1 - i)) & 1 for i in range(width)]


def integer(bit_array: list[int]) -> int:
    value = 0
    for bit in bit_array:
        value = (value << 1) | bit
    return value


def rol(value: int, amount: int) -> int:
    if amount == 0:
        return value
    return ((value << amount) | (value >> (64 - amount))) & ((1 << 64) - 1)


def ror(value: int, amount: int) -> int:
    if amount == 0:
        return value
    return ((value >> amount) | (value << (64 - amount))) & ((1 << 64) - 1)


def check_pi() -> None:
    """Check the inverse-coordinate rule, forward matrix, and optimized formula."""
    destinations = set()
    for i in range(5):
        for j in range(5):
            di = (4 * i + 4 * j) % 5
            dj = (i + 3 * j) % 5
            si = (di + 2 * dj) % 5
            sj = (3 * di + 3 * dj) % 5
            assert (si, sj) == (i, j)
            assert PI_FORWARD[5 * i + j] == (di, dj)
            destinations.add((di, dj))
    assert len(destinations) == 25


def chi(state: list[list[list[int]]]) -> list[list[list[int]]]:
    out = [[[0] * 64 for _ in range(5)] for _ in range(5)]
    for j in range(5):
        for k in range(64):
            a = [state[i][j][k] for i in range(5)]
            out[0][j][k] = (
                (a[0] & a[2] & a[3])
                ^ (a[2] & a[3] & a[4])
                ^ (a[0] & a[4])
                ^ (a[3] & a[4])
                ^ a[1]
            )
            out[1][j][k] = (a[1] & a[3] & a[4]) ^ (a[0] & a[1]) ^ a[2]
            out[2][j][k] = (a[1] & a[2]) ^ a[3]
            out[3][j][k] = (a[2] & a[3]) ^ a[4]
            out[4][j][k] = (a[3] & a[4]) ^ a[0]
    return out


def theta(state: list[list[list[int]]]) -> list[list[list[int]]]:
    out = [[[0] * 64 for _ in range(5)] for _ in range(5)]
    for i in range(5):
        lanes = [integer(state[i][j]) for j in range(5)]
        e = 0
        for lane in lanes:
            e ^= lane
        f = 0
        for lane, t in zip(lanes, THETA[i]):
            f ^= rol(lane, t)
        for j, lane in enumerate(lanes):
            out[i][j] = bits(lane ^ ror(e, THETA[i][j]) ^ f, 64)
    return out


def pi(state: list[list[list[int]]]) -> list[list[list[int]]]:
    out = [[[0] * 64 for _ in range(5)] for _ in range(5)]
    for source, destination in enumerate(PI_FORWARD):
        i, j = divmod(source, 5)
        di, dj = destination
        out[di][dj] = state[i][j][:]
    return out


def permutation(bit_array: list[int]) -> list[int]:
    assert len(bit_array) == 1600
    state = [
        [
            [bit_array[(i * 5 + j) * 64 + k] for k in range(64)]
            for j in range(5)
        ]
        for i in range(5)
    ]
    for r in range(16):
        round_constant = bits(RC[r], 64)
        for k, bit in enumerate(round_constant):
            state[0][0][k] ^= bit
        state = pi(theta(chi(state)))
    return [state[i][j][k] for i in range(5) for j in range(5) for k in range(64)]


def first_chunk(c: int, fid: int, final_block: list[int], d: int = 0) -> int:
    """First 1088-bit squeeze chunk for a one-final-block message."""
    assert len(final_block) == 512
    assert d in (0, 1)
    n = (1 << 63) * fid + c
    assert n < (1 << 64)
    state0 = bits(n, 1536)
    x = state0 + final_block
    u = x[-1536:]
    v = x[-1088:]
    squeeze_input = [1, d] + [0] * 62 + u
    output = permutation(squeeze_input)
    return integer([a ^ b for a, b in zip(output[-1088:], v)])


def main() -> None:
    check_pi()
    print("pi: all three mathematical descriptions agree on 25/25 lanes")

    # This is the sole final block for both empty and 1||0^511, but d differs.
    final_block = bits(1, 512)
    values = {
        (c, fid): first_chunk(c, fid, final_block)
        for c in (512, 768, 1024)
        for fid in (0, 1)
    }
    print("first chunk for final block 1||0^511:")
    for key, value in values.items():
        print(f"  {key}: {value:0272x}")
    print(f"distinct profile values: {len(set(values.values()))}")

    empty_chunk = first_chunk(512, 0, final_block, d=0)
    z_chunk = first_chunk(512, 0, final_block, d=1)
    print(f"empty vs 1||0^511 (Laurus-512): different={empty_chunk != z_chunk}")


if __name__ == "__main__":
    main()
