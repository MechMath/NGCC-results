#!/usr/bin/env python3
"""Independent executable model of TaiChi v2.0 Sections 1.2--1.7.

This module models bitstrings as nonnegative integers: bit t of the integer is
message/stream bit t (the first bit is the least-significant bit).  This makes
concatenation x || y the integer x | (y << len(x)).  The PDF specifies the
abstract bitstring semantics but does not specify a byte-to-bit convention.
"""

from __future__ import annotations

from dataclasses import dataclass

MASK64 = (1 << 64) - 1

# Algorithm 6, Table 1.3.
MRM_N1 = [0, 1, 2, 4, 3, 5, 6, 7, 13, 14, 15, 16, 15, 18, 11, 20]
MRM_N2 = [1, 2, 4, 3, 5, 6, 0, 11, 8, 9, 10, 12, 17, 14, 19, 13]
MRM_M = [8, 0, 0, 0, 0, 0, 23, 62, 35, 14, 48, 1, 57, 63, 58, 22]
OUT_ROT = [0, 15, 48, 63, 6, 33]
RC_POS = [0, 2, 3, 6, 13, 28, 59]


def rol64(x: int, n: int) -> int:
    n %= 64
    return ((x << n) | (x >> (64 - n))) & MASK64 if n else x


def sbox5(x: int) -> int:
    """The five bitsliced equations of Algorithm 4, scalarised."""
    a = [(x >> i) & 1 for i in range(5)]
    b0 = a[1] ^ (a[0] & a[1]) ^ a[2] ^ (a[1] & a[2]) ^ a[3] ^ (a[3] & a[4])
    b1 = 1 ^ a[1] ^ (a[0] & a[3]) ^ (a[1] & a[3]) ^ a[4] ^ (a[2] & a[4])
    b2 = (a[1] & a[2]) ^ a[3] ^ (a[2] & a[3]) ^ a[4] ^ (a[0] & a[4])
    b3 = (a[0] & a[2]) ^ (a[1] & a[3]) ^ (a[2] & a[3]) ^ a[4]
    b4 = a[0] ^ (a[2] & a[3]) ^ (a[1] & a[4])
    return b0 | (b1 << 1) | (b2 << 2) | (b3 << 3) | (b4 << 4)


SBOX = tuple(sbox5(x) for x in range(32))


def q_layer(a: list[int]) -> list[int]:
    """Algorithm 5, with each row represented by five 64-bit words."""
    out = [0] * 30
    for row in range(6):
        a0, a1, a2, a3, a4 = a[5 * row : 5 * row + 5]
        out[5 * row] = (
            a1 ^ (a0 & a1) ^ a2 ^ (a1 & a2) ^ a3 ^ (a3 & a4)
        ) & MASK64
        out[5 * row + 1] = (
            MASK64
            ^ a1
            ^ (a0 & a3)
            ^ (a1 & a3)
            ^ a4
            ^ (a2 & a4)
        ) & MASK64
        out[5 * row + 2] = (
            (a1 & a2) ^ a3 ^ (a2 & a3) ^ a4 ^ (a0 & a4)
        ) & MASK64
        out[5 * row + 3] = (
            (a0 & a2) ^ (a1 & a3) ^ (a2 & a3) ^ a4
        ) & MASK64
        out[5 * row + 4] = (a0 ^ (a2 & a3) ^ (a1 & a4)) & MASK64
    return out


def mrm6(y: list[int]) -> list[int]:
    """Algorithm 6.  The iteration is deliberately in-place."""
    y = y[:]
    for i in range(6, 22):
        y.append(0)
        y[i] = (y[MRM_N1[i - 6]] ^ rol64(y[MRM_N2[i - 6]], MRM_M[i - 6])) & MASK64
    return [rol64(y[16 + k], OUT_ROT[k]) for k in range(6)]


def l_layer(a: list[int]) -> list[int]:
    """Algorithm 7, one independent six-word MRM per column."""
    out = [0] * 30
    for j in range(5):
        for i, y in enumerate(mrm6([a[5 * i + j] for i in range(6)])):
            out[5 * i + j] = y
    return out


PI = [((10 * (n + 1)) % 31) - 1 for n in range(30)]


def pi_layer(a: list[int]) -> list[int]:
    out = [0] * 30
    for n, n2 in enumerate(PI):
        out[n2] = a[n]
    return out


def round_constants(count: int = 120) -> list[int]:
    """Algorithm 8's 7-bit LFSR embedded at P and emitted little-endian."""
    state = [1, 0, 0, 0, 0, 0, 0]  # index l is state bit l
    constants = []
    for _ in range(count):
        c = 0
        for bit, pos in zip(state, RC_POS):
            c |= bit << pos
        constants.append(c)
        s6 = state[6]
        state = [s6, state[0] ^ s6, state[1], state[2], state[3], state[4], state[5]]
    return constants


RC = round_constants()


def permutation(x: int, b: int, rounds: int = 12) -> int:
    """TaiChi P1920 with domain b=1 or 2."""
    if not 1 <= b <= 2:
        raise ValueError("b must be 1 or 2")
    if not 0 <= rounds <= 12:
        raise ValueError("rounds must be in 0..12")
    a = [(x >> (64 * n)) & MASK64 for n in range(30)]
    for t in range(rounds):
        a = l_layer(a)
        a = q_layer(a)
        a = pi_layer(a)
        for j in range(5):
            a[j] ^= RC[(b - 1) * 60 + 5 * t + j]
    return sum(v << (64 * n) for n, v in enumerate(a))


def xor_prefix(x: int, y: int, width: int) -> int:
    return (x ^ y) & ((1 << width) - 1)


def concat(x: int, xbits: int, y: int) -> int:
    return x | (y << xbits)


@dataclass(frozen=True)
class Profile:
    name: str
    d: int
    r: int
    c: int

    @property
    def block_lanes(self) -> int:
        assert self.r % 64 == 0
        return self.r // 64

    @property
    def capacity_lanes(self) -> int:
        assert self.c % 64 == 0
        return self.c // 64


PROFILES = {
    512: Profile("TaiChi-512", 512, 1408, 512),
    768: Profile("TaiChi-768", 768, 1152, 768),
    1024: Profile("TaiChi-1024", 1024, 896, 1024),
}
TAGS = {"Ab": 1, "Fin": 2, "Sq": 3}


def split_input(x: int, r: int) -> tuple[int, int]:
    return x & ((1 << r) - 1), x >> r


def step(
    state: tuple[int, int, int],
    block: int,
    tag: str,
    p: Profile,
    rounds: int = 12,
) -> tuple[int, int, int]:
    s, l, rbranch = state
    block &= (1 << p.r) - 1
    x = s ^ block
    a, b = split_input(permutation(concat(x, p.r, l ^ TAGS[tag]), 1, rounds), p.r)
    s2, c = split_input(permutation(concat(a, p.r, rbranch ^ b), 2, rounds), p.r)
    return s2, c, b ^ c


def pad_bits(message: int, mlen: int, r: int) -> tuple[int, int, int]:
    j = (-(mlen + 2)) % r
    n = mlen + 2 + j
    padded = message | (1 << mlen) | (1 << (n - 1))
    return padded, n, j


def chunks(x: int, nbits: int, width: int) -> list[int]:
    return [(x >> off) & ((1 << width) - 1) for off in range(0, nbits, width)]


def hash_bits(
    message: int, mlen: int, d: int, rounds: int = 12, trace: bool = False
) -> int | tuple[int, dict]:
    p = PROFILES[d]
    padded, plen, j = pad_bits(message, mlen, p.r)
    blocks = chunks(padded, plen, p.r)
    state = (0, 0, 0)
    states = [state]
    tags = []
    for block in blocks[:-1]:
        state = step(state, block, "Ab", p, rounds)
        states.append(state)
        tags.append("Ab")
    state = step(state, blocks[-1], "Fin", p, rounds)
    states.append(state)
    tags.append("Fin")
    z, zbits = state[0], p.r
    squeezes = 0
    while zbits < d:
        state = step(state, 0, "Sq", p, rounds)
        states.append(state)
        tags.append("Sq")
        z = concat(z, zbits, state[0])
        zbits += p.r
        squeezes += 1
    result = z & ((1 << d) - 1)
    if not trace:
        return result
    return result, {
        "padding_bits": j,
        "padded_length": plen,
        "blocks": blocks,
        "tags": tags,
        "states": states,
        "squeezes": squeezes,
    }


def bytes_to_bits_lsb(data: bytes) -> tuple[int, int]:
    """An explicitly chosen byte convention, not supplied by the PDF."""
    return int.from_bytes(data, "little"), 8 * len(data)


def bits_to_bytes_lsb(x: int, nbits: int) -> bytes:
    assert nbits % 8 == 0
    return x.to_bytes(nbits // 8, "little")


def hash_bytes(data: bytes, d: int, rounds: int = 12) -> bytes:
    x, nbits = bytes_to_bits_lsb(data)
    return bits_to_bytes_lsb(hash_bits(x, nbits, d, rounds), d)

