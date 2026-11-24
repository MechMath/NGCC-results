#!/usr/bin/env python3
"""Second CHIME representation, using explicit most-significant-first bit lists."""

from __future__ import annotations

SBOX = (0, 5, 3, 2, 6, 1, 4, 7)
MASK64 = (1 << 64) - 1


def xor(a: list[int], b: list[int]) -> list[int]:
    return [x ^ y for x, y in zip(a, b)]


def rotl(x: list[int], n: int) -> list[int]:
    out = x[:]
    for word in range(4):
        old = x[64 * word : 64 * word + 64]
        out[64 * word : 64 * word + 64] = [
            old[(p + n) % 64] for p in range(64)
        ]
    return out


def rotr(x: list[int], n: int) -> list[int]:
    return rotl(x, 64 - n)


def shl(x: list[int], n: int) -> list[int]:
    out = x[:]
    for word in range(4):
        old = x[64 * word : 64 * word + 64]
        out[64 * word : 64 * word + 64] = [
            old[p + n] if p + n < 64 else 0 for p in range(64)
        ]
    return out


def shr(x: list[int], n: int) -> list[int]:
    out = x[:]
    for word in range(4):
        old = x[64 * word : 64 * word + 64]
        out[64 * word : 64 * word + 64] = [
            old[p - n] if p >= n else 0 for p in range(64)
        ]
    return out


def p32(x: list[int]) -> list[int]:
    q = [x[32 * i : 32 * (i + 1)] for i in range(8)]
    a1, b1, c1, d1, a0, b0, c0, d0 = q
    return sum((d1, a1, b1, c1, d0, a0, b0, c0), [])


def p64(x: list[int]) -> list[int]:
    a, b, c, d = [x[64 * i : 64 * (i + 1)] for i in range(4)]
    return b + c + d + a


def swap64(x: list[int]) -> list[int]:
    a, b, c, d = [x[64 * i : 64 * (i + 1)] for i in range(4)]
    return b + a + d + c


def swap128(x: list[int]) -> list[int]:
    return x[128:] + x[:128]


def linear(state: list[list[int]]) -> list[list[int]]:
    a0, a1, b0, b1, c0, c1 = [x[:] for x in state]
    b1 = xor(b1, p32(c1))
    b0 = xor(b0, a1)
    c0 = xor(c0, rotl(a0, 29))
    b1 = xor(b1, rotl(a1, 31))
    c1 = xor(c1, rotl(a0, 13))
    c0 = xor(c0, b1)
    a0 = p64(a0)
    c1 = xor(c1, p32(b1))
    a1 = swap128(a1)
    a0 = xor(a0, swap64(c0))
    a1 = xor(a1, p32(b0))
    b1 = xor(b1, shl(a0, 7))
    c1 = xor(c1, shr(a1, 5))
    return [a0, a1, b0, b1, c0, c1]


def chi(state: list[list[int]], r: int) -> list[list[int]]:
    a0, a1, b0, b1, c0, c1 = state
    if r % 2 == 0:
        groups = ((a0, b0, c0), (a1, b1, c1))
    else:
        groups = ((a0, b1, c1), (a1, b0, c0))
    output = [[], [], [], [], [], []]
    for start, (x, y, z) in ((0, groups[0]), (1, groups[1])):
        xo, yo, zo = [], [], []
        for i in range(256):
            value = SBOX[(x[i] << 2) | (y[i] << 1) | z[i]]
            xo.append((value >> 2) & 1)
            yo.append((value >> 1) & 1)
            zo.append(value & 1)
        if r % 2 == 0:
            output[0 if start == 0 else 1] = xo
            output[2 if start == 0 else 3] = yo
            output[4 if start == 0 else 5] = zo
        else:
            output[0 if start == 0 else 1] = xo
            output[3 if start == 0 else 2] = yo
            output[5 if start == 0 else 4] = zo
    return list(output)


def tau(state: list[list[int]], r: int) -> list[list[int]]:
    a0, a1, b0, b1, c0, c1 = state
    if (r // 3) % 2 == 0:
        return [c1, a0, a1, b0, b1, c0]
    return [a1, b0, b1, c0, c1, a0]


def round_constant(i: int) -> int:
    return (
        0xDEADBEEF00000000
        ^ i
        ^ ((0x9E3779B97F4A7C15 * (i + 1)) & MASK64)
    ) & MASK64


def rnd(state: list[list[int]], r: int) -> list[list[int]]:
    state = linear(state)
    constant = [int(bit) for bit in f"{round_constant(r):064b}"] * 4
    state[0] = xor(state[0], constant)
    return tau(chi(state, r), r)


def permute(state: list[list[int]], rounds: int) -> list[list[int]]:
    for r in range(rounds):
        state = rnd(state, r)
    return state


def bits(text: str) -> list[int]:
    return [int(c) for c in text]


def pad(message: str, rate: int) -> str:
    return message + "1" + "0" * ((-len(message) - 2) % rate) + "1"


def hash_bits(message: str, rate: int, capacity: int, rounds: int, profile: str) -> str:
    padded = pad(message, rate)
    state = [[0] * 256 for _ in range(6)]
    for offset in range(0, len(padded), rate):
        block = bits(padded[offset : offset + rate])
        for i, bit in enumerate(block):
            state[i // 256][i % 256] ^= bit
        old = [a[:] for a in state]
        state = permute(state, rounds)
        if profile == "CHIME-1024":
            for i in range(capacity):
                state[(rate + i) // 256][(rate + i) % 256] ^= old[(rate + i) // 256][(rate + i) % 256]
    flat = sum(state, [])
    if profile == "CHIME-1024":
        flat[-1] ^= 1
        return "".join(map(str, flat[-1024:]))
    return "".join(map(str, flat[:512]))


def state_bits(state: list[list[int]]) -> str:
    return "".join("".join(map(str, a)) for a in state)


if __name__ == "__main__":
    assert round_constant(0) == 0x409AC7567F4A7C15
    assert round_constant(19) == 0x82F83C92F1D1B1B7
    print(state_bits(permute([[0] * 256 for _ in range(6)], 1))[:64])
