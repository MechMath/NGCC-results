#!/usr/bin/env python3
"""Second, flat-bit independent V1 implementation for the API witness.

This uses one list of 576 state bits rather than nine integer lanes, so its
S-box and linear layer are evaluated by column/bit indexing from the rendered
specification rather than reusing wchain_witness.py's word operations.
"""

from __future__ import annotations

PI = [0, 7, 5, 3, 1, 8, 6, 4, 2]
ROWS = [
    [(0, 5), (1, 22), (2, 3), (3, 28), (7, 27)],
    [(1, 39), (2, 59), (3, 45), (4, 3), (8, 9)],
    [(2, 54), (3, 6), (4, 20), (5, 8), (0, 48)],
    [(3, 0), (4, 57), (5, 55), (6, 46), (1, 28)],
    [(4, 61), (5, 38), (6, 0), (7, 44), (2, 52)],
    [(5, 29), (6, 10), (7, 37), (8, 19), (3, 7)],
    [(6, 56), (7, 5), (8, 50), (0, 27), (4, 13)],
    [(7, 40), (8, 10), (0, 11), (1, 54), (5, 14)],
    [(8, 3), (0, 38), (1, 36), (2, 17), (6, 13)],
]
DROT = [0, 1, 10, 20, 25, 32, 41, 46, 50]
PI_HEX = (
    "243F6A8885A308D313198A2E03707344"
    "A4093822299F31D0082EFA98EC4E6C89"
    "452821E638D01377BE5466CF34E90C6C"
)
RC = [int(PI_HEX[4 * i : 4 * i + 4], 16) for i in range(24)]


def s9(x: int) -> int:
    out = 0
    for i in range(9):
        a = (x >> i) & 1
        b = (x >> ((i + 1) % 9)) & 1
        c = (x >> ((i + 2) % 9)) & 1
        out |= (a ^ (1 ^ ((1 - b) & c))) << i
    return out


S9 = [s9(x) for x in range(512)]
assert len(set(S9)) == 512


def idx(lane: int, z: int) -> int:
    # z is the little-endian bit index inside the 64-bit lane, while the
    # serialized bit list stores each lane most-significant bit first.
    return lane * 64 + (63 - z % 64)


def s_layer(state: list[int]) -> list[int]:
    out = [0] * 576
    for z in range(64):
        x = 0
        for lane in range(9):
            x |= state[idx(lane, z)] << lane
        y = S9[x]
        for lane in range(9):
            out[idx(lane, z)] = (y >> lane) & 1
    return out


def pi_layer(state: list[int]) -> list[int]:
    out = [0] * 576
    for in_lane in range(9):
        for z in range(64):
            out[idx(PI[in_lane], z)] = state[idx(in_lane, z)]
    return out


def mix(state: list[int]) -> list[int]:
    out = [0] * 576
    for out_lane in range(9):
        for z in range(64):
            value = 0
            for in_lane, rotation in ROWS[out_lane]:
                value ^= state[idx(in_lane, z - rotation)]
            out[idx(out_lane, z)] = value
    return out


def iota(state: list[int], round_index: int) -> list[int]:
    out = state[:]
    constant = RC[round_index]
    for lane in range(9):
        for bit in range(16):
            if (constant >> bit) & 1:
                out[idx(lane, bit + lane)] ^= 1
    return out


def round_v1(state: list[int], round_index: int) -> list[int]:
    return mix(pi_layer(s_layer(iota(state, round_index))))


def mef(state: list[int]) -> list[int]:
    rotated = [0] * 576
    for lane in range(9):
        for z in range(64):
            rotated[idx(lane, z)] = state[idx(lane, z - DROT[lane])]
    return s_layer(rotated)


def xor(a: list[int], b: list[int]) -> list[int]:
    return [x ^ y for x, y in zip(a, b)]


def compress(v: list[int], block: list[int]) -> list[int]:
    rounds = 18
    injections = [block[:576], block[576:]]
    for _ in range(2, rounds + 1):
        injections.append(xor(mef(injections[-1]), injections[-2]))
    state = v[:]
    for j in range(1, rounds + 1):
        state = round_v1(xor(state, injections[j - 1]), j - 1)
    return xor(xor(state, injections[rounds]), v)


def hash_v1(bits: str) -> str:
    mu = 1152
    padded = bits + "1" + "0" * ((-(len(bits) + 1)) % mu)
    blocks = [
        [int(bit) for bit in padded[i : i + mu]]
        for i in range(0, len(padded), mu)
    ]
    checksum = [0] * mu
    for block in blocks:
        checksum = [a ^ b for a, b in zip(checksum, block)]
    previous = [0] * 576
    current = [0] * 576
    for block in blocks:
        current, previous = xor(compress(current, block), previous), current
    final = compress(current, checksum)
    return f"{int(''.join(map(str, final[:512])), 2):0128x}"


def main() -> None:
    for bit in ("1", "0"):
        print(bit, hash_v1(bit))


if __name__ == "__main__":
    main()
