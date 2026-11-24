#!/usr/bin/env python3
"""Independent integer-register check of the list-based AXIS probe."""

from __future__ import annotations

import axis_probe

CONSTANTS = [int(value, 16) for value in axis_probe.CONSTANTS_HEX]
EXL = axis_probe.EXL
UPL = axis_probe.UPL
MASK = (1 << 192) - 1


def bit(word: int, index: int) -> int:
    return (word >> index) & 1


def sbox(*values: int) -> int:
    x5, x4, x3, x2, x1, x0 = values
    return (x5 & x4) ^ (x3 & x2) ^ (x1 & x0)


def up_res(state: list[int], j: int, message_bit: int) -> None:
    current = state[j]
    tau = sbox(
        bit(state[(j + 5) % 8], EXL[3]),
        bit(state[(j + 5) % 8], EXL[2]),
        bit(state[(j + 3) % 8], EXL[5]),
        bit(state[(j + 3) % 8], EXL[1]),
        bit(state[(j + 1) % 8], EXL[4]),
        bit(state[(j + 1) % 8], EXL[0]),
    )
    own = sbox(*(bit(current, EXL[i]) for i in (5, 2, 4, 1, 3, 0)))
    control = message_bit ^ own ^ tau ^ bit(state[(j - 1) % 8], EXL[6])
    t0 = bit(current, EXL[2]) ^ bit(current, EXL[1]) ^ bit(current, EXL[0]) ^ control
    t1 = bit(current, EXL[5]) ^ bit(current, EXL[4]) ^ bit(current, EXL[3]) ^ control
    for index in (UPL[2], UPL[1], UPL[0]):
        current ^= t1 << index
    for index in (UPL[5], UPL[4], UPL[3]):
        current ^= t0 << index
    state[j] = ((current >> 1) | ((current & 1) << 191)) & MASK


def up_full(state: list[int], mu: int, nu: int) -> None:
    for j in range(8):
        up_res(state, j, mu if j % 2 == 0 else nu)


def gen_digest(state: list[int]) -> tuple[int, int]:
    mu = bit(state[6], 0) ^ bit(state[4], 0) ^ (bit(state[2], 0) & bit(state[0], 0))
    nu = bit(state[7], 0) ^ bit(state[5], 0) ^ (bit(state[3], 0) & bit(state[1], 0))
    return mu, nu


def pad(message: list[int]) -> list[int]:
    length = len(message)
    zero_count = (-length - 3) % 64
    length_bits = [int(value) for value in format(length, "064b")]
    return message + [1] + [0] * (zero_count + 1) + [1] + length_bits


def hash_bits(message: list[int], variant: int) -> list[int]:
    padded = pad(message)
    state = CONSTANTS[:]

    if variant == 512:
        for i in range(0, len(padded), 2):
            up_full(state, padded[i + 1], padded[i])
    elif variant == 1024:
        for value in padded:
            up_full(state, value, value)
    elif variant == 768:
        remainder = len(padded) % 192
        if remainder == 0:
            beats = 2 * len(padded) // 3
        elif remainder == 64:
            beats = (2 * len(padded) + 64) // 3
        elif remainder == 128:
            beats = (2 * len(padded) + 32) // 3
        else:
            raise AssertionError(remainder)
        i = 0
        for t in range(beats):
            tail = (remainder == 64 and t >= beats - 64) or (
                remainder == 128 and t >= beats - 32
            )
            if t % 2 == 0 or tail:
                up_full(state, padded[i], padded[i])
                i += 1
            else:
                up_full(state, padded[i + 1], padded[i])
                i += 2
        assert i == len(padded)
    else:
        raise ValueError(variant)

    digest_beats = {512: 256, 768: 512, 1024: 1024}[variant]
    stream = []
    while len(stream) < 8 * (1024 + digest_beats):
        for constant in CONSTANTS:
            stream.extend(bit(constant, i) for i in range(192))

    def refresh(offset: int) -> None:
        for j in range(8):
            up_res(state, j, stream[offset + j])

    for beat in range(1024):
        refresh(8 * beat)
    pieces = []
    for beat in range(digest_beats):
        mu, nu = gen_digest(state)
        if variant == 512 or (variant == 768 and beat % 2 == 1):
            pieces.extend((mu, nu))
        else:
            pieces.append(mu)
        refresh(8 * (1024 + beat))
    return list(reversed(pieces))


if __name__ == "__main__":
    message = [int(value) for value in "00000001"]
    for profile in (512, 768, 1024):
        integer_output = hash_bits(message, profile)
        list_output = axis_probe.hash_bits(message, profile)
        assert integer_output == list_output
        print(profile, axis_probe.bits_to_hex(integer_output))
