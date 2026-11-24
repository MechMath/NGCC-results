#!/usr/bin/env python3
"""Independent WChain V1 model for the partial-byte API witness.

This is a research note, not a crypto_run-backed execution. It implements the
rendered specification, including both overbars in the chi formula on page 11.
A Version-II path is retained below but is not used as evidence here because its
separate seed/table transcription has not been independently matched in this file.
"""

from __future__ import annotations

MASK64 = (1 << 64) - 1
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
DELTA = [11, 21, 19, 21, 43, 5, 3, 10, 5]
DROT = [0, 1, 10, 20, 25, 32, 41, 46, 50]
PI_HEX = (
    "243F6A8885A308D313198A2E03707344"
    "A4093822299F31D0082EFA98EC4E6C89"
    "452821E638D01377BE5466CF34E90C6C"
)
ROUND_CONSTANTS = [
    int(PI_HEX[4 * i : 4 * i + 4], 16) for i in range(len(PI_HEX) // 4)
]


def rotl(x: int, r: int) -> int:
    r %= 64
    return ((x << r) | (x >> (64 - r))) & MASK64 if r else x


def chi(half: list[int]) -> list[int]:
    out = [0] * 9
    for z in range(64):
        a = [(half[i] >> z) & 1 for i in range(9)]
        for i in range(9):
            # The rendered PDF has both an inner bar on a_{i+1} and an outer
            # bar over the product: b_i = a_i XOR NOT(NOT(a_{i+1}) AND a_{i+2}).
            inner = (1 - a[(i + 1) % 9]) & a[(i + 2) % 9]
            bit = a[i] ^ (1 - inner)
            out[i] |= bit << z
    return out


def pi_layer(half: list[int]) -> list[int]:
    out = [0] * 9
    for i in range(9):
        out[PI[i]] = half[i]
    return out


def mix(half: list[int], right: bool = False) -> list[int]:
    out = [0] * 9
    for i in range(9):
        for j, a in ROWS[i]:
            out[i] ^= rotl(half[j], a + (DELTA[i] if right else 0))
    return out


def mef(half: list[int]) -> list[int]:
    return chi([rotl(half[i], DROT[i]) for i in range(9)])


def round_v1(state: list[int], round_index: int) -> list[int]:
    state = [state[i] ^ rotl(ROUND_CONSTANTS[round_index], i) for i in range(9)]
    return mix(pi_layer(chi(state)))


def round_v2(state: list[int], round_index: int) -> list[int]:
    left, right = state[:9], state[9:]
    left = [left[i] ^ rotl(ROUND_CONSTANTS[round_index], i) for i in range(9)]
    right = [
        right[i] ^ rotl(ROUND_CONSTANTS[round_index], i + 9) for i in range(9)
    ]
    left, right = pi_layer(chi(left)), pi_layer(chi(right))
    for i in (0, 1, 3, 4, 6):
        left[i], right[i] = right[i], left[i]
    return mix(left) + mix(right, right=True)


def bits_to_lanes(bits: str) -> list[int]:
    assert len(bits) % 64 == 0
    return [int(bits[i : i + 64], 2) for i in range(0, len(bits), 64)]


def lanes_to_bits(lanes: list[int], bit_count: int | None = None) -> str:
    out = "".join(f"{lane:064b}" for lane in lanes)
    return out if bit_count is None else out[:bit_count]


def compress_v1(v: list[int], block: list[int]) -> list[int]:
    rounds = 18
    e0, e1 = block[:9], block[9:]
    injections = [e0, e1]
    for _ in range(2, rounds + 1):
        injections.append(
            [a ^ b for a, b in zip(mef(injections[-1]), injections[-2])]
        )
    state = v[:]
    for j in range(1, rounds + 1):
        state = [a ^ b for a, b in zip(state, injections[j - 1])]
        state = round_v1(state, j - 1)
    return [
        a ^ b ^ c for a, b, c in zip(state, injections[rounds], v)
    ]


def compress_v2(v: list[int], block: list[int]) -> list[int]:
    rounds = 24
    left = [[], []]
    right = [[], []]
    left[0], left[1] = block[:9], block[9:18]
    right[0], right[1] = block[18:27], block[27:36]
    for j in range(2, rounds + 1):
        left.append(
            [a ^ b for a, b in zip(mef(left[-1]), left[-2])]
        )
        right.append(
            [a ^ b for a, b in zip(mef(right[-1]), right[-2])]
        )
    state = v[:]
    for j in range(1, rounds + 1):
        injection = left[j - 1] + right[j - 1]
        state = [a ^ b for a, b in zip(state, injection)]
        state = round_v2(state, j - 1)
    final = left[rounds] + right[rounds]
    return [a ^ b ^ c for a, b, c in zip(state, final, v)]


def wchain(bits: str, version: int) -> str:
    digest_bits = 512 if version == 1 else 1024
    state_bits = 576 if version == 1 else 1152
    block_bits = 2 * state_bits
    padded = bits + "1" + "0" * ((-(len(bits) + 1)) % block_bits)
    blocks = [
        bits_to_lanes(padded[i : i + block_bits])
        for i in range(0, len(padded), block_bits)
    ]
    checksum = [0] * (2 * state_bits // 64)
    for block in blocks:
        checksum = [a ^ b for a, b in zip(checksum, block)]
    previous, current = [0] * (state_bits // 64), [0] * (state_bits // 64)
    compress = compress_v1 if version == 1 else compress_v2
    for block in blocks:
        nxt = compress(current, block)
        nxt = [a ^ b for a, b in zip(nxt, previous)]
        previous, current = current, nxt
    final = compress(current, checksum)
    return lanes_to_bits(final, digest_bits)


def unpack_first_bits(buffer: bytes, bit_count: int, msb_first: bool) -> str:
    order = range(7, -1, -1) if msb_first else range(8)
    bits = "".join(
        str((byte >> bit) & 1) for byte in buffer for bit in order
    )
    return bits[:bit_count]


def digest_hex(bits: str) -> str:
    return f"{int(bits, 2):0{len(bits) // 4}x}"


def main() -> None:
    outputs = {}
    for msb_first in (True, False):
        bits = unpack_first_bits(b"\x80", 1, msb_first)
        outputs[bits] = digest_hex(wchain(bits, 1))
    assert outputs["1"] != outputs["0"]
    print("Version 1")
    print(f"  M=1: {outputs['1']}")
    print(f"  M=0: {outputs['0']}")


if __name__ == "__main__":
    main()
