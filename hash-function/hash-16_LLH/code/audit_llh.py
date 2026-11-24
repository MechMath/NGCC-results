#!/usr/bin/env python3
"""Minimal LLH-256 implementation for the message-length encoding audit.

Only the ambiguity needed by the audit is varied: the byte/bit placement of the
64-bit message length in the initial state. All other choices follow the pinned
specification and its stated little-endian message convention.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass


SHIFTS = [
    3, 16, 13, 26, 8, 29, 2, 23, 21, 18, 31, 28,
    10, 15, 4, 9, 7, 20, 17, 30, 12, 1, 6, 27,
]

CONSTANTS = [
    0xB7E15162, 0x8AED2A6A, 0xBF715880, 0x9CF4F3C7,
    0x62E7160F, 0x38B4DA56, 0xA784D904, 0x5190CFEF,
    0x324E7738, 0x926CFBE5, 0xF4BF8D8D, 0x8C31D763,
    0xDA06C80A, 0xBB1185EB, 0x4F7C7B57, 0x57F59584,
]

# At output position p, use the input position listed in Table 2-3.
DERANGEMENT = [
    4, 9, 18, 23,
    8, 1, 22, 15,
    12, 17, 6, 3,
    20, 5, 10, 19,
    0, 21, 14, 11,
    16, 13, 2, 7,
]

D = [
    [0, 1, 1, 1],
    [1, 0, 1, 1],
    [1, 1, 0, 1],
    [1, 1, 1, 0],
]


def ror6(x: int, n: int) -> int:
    return ((x >> n) | (x << (6 - n))) & 0x3F


def s6(x: int) -> int:
    return (x ^ ror6(x, 2) ^ (ror6(x, 1) & ror6(x, 3)) ^ 0x1B) & 0x3F


def rol32(x: int, n: int) -> int:
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def subcolumn(state: list[int]) -> list[int]:
    out = [0] * 24
    for j in range(32):
        v = [(word >> j) & 1 for word in state]
        y = [0] * 24
        for c in range(4):
            x = sum(v[4 * r + c] << r for r in range(6))
            z = s6(x)
            for r in range(6):
                y[4 * r + c] = (z >> r) & 1
        z = [y[p] for p in DERANGEMENT]
        for r in range(6):
            row = z[4 * r:4 * r + 4]
            row = [sum(row[i] and D[i][j] for i in range(4)) & 1 for j in range(4)]
            for c, bit in enumerate(row):
                out[4 * r + c] |= bit << j
    return out


def permutation(state: list[int]) -> list[int]:
    state = state.copy()
    for rc in CONSTANTS:
        state = subcolumn(state)
        state = [rol32(word, SHIFTS[i]) for i, word in enumerate(state)]
        state[23] ^= rc
    return state


def initial_state(length: int, length_order: str) -> list[int]:
    state = [0] * 24
    lo, hi = length & 0xFFFFFFFF, (length >> 32) & 0xFFFFFFFF
    if length_order == "low-word-first":
        state[22], state[23] = lo, hi
    elif length_order == "high-word-first":
        state[22], state[23] = hi, lo
    else:
        raise ValueError(length_order)
    return state


def padded_words(message: bytes) -> list[int]:
    r = 256
    bits = len(message) * 8
    if bits % r:
        pad_bits = r - (bits % r)
        message += b"\xff" * (pad_bits // 8)
    assert len(message) % 32 == 0
    return [
        int.from_bytes(message[i:i + 4], "little")
        for i in range(0, len(message), 4)
    ]


def llh256(message: bytes, length_order: str) -> bytes:
    state = initial_state(len(message) * 8, length_order)
    words = padded_words(message)
    for i in range(0, len(words), 8):
        block = words[i:i + 8]
        state = permutation(state)
        for j, word in enumerate(block):
            state[j] ^= word
    state = permutation(state)
    return b"".join(word.to_bytes(4, "little") for word in state[:8])


@dataclass(frozen=True)
class Result:
    message_hex: str
    low_word_first: str
    high_word_first: str


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--message-hex", default="00")
    args = parser.parse_args()
    message = bytes.fromhex(args.message_hex)
    result = Result(
        message_hex=message.hex(),
        low_word_first=llh256(message, "low-word-first").hex(),
        high_word_first=llh256(message, "high-word-first").hex(),
    )
    print(result)


if __name__ == "__main__":
    main()
