#!/usr/bin/env python3
"""Exact scalar reference for the April 2026 CHIME specification.

The six 256-bit arrays are Python integers in their big-endian bit-string
order: array bit 0 is the most significant bit.  A 256-bit array is split
into four big-endian 64-bit words for word-local rotations.
"""

from __future__ import annotations

import hashlib
import random
from dataclasses import dataclass


M256 = (1 << 256) - 1
M64 = (1 << 64) - 1
SBOX = (0, 5, 3, 2, 6, 1, 4, 7)


def rol64(x: int, n: int) -> int:
    n %= 64
    return ((x << n) | (x >> (64 - n))) & M64 if n else x


def ror64(x: int, n: int) -> int:
    return rol64(x, -n)


def per_word(x: int, fn) -> int:
    out = 0
    for shift in (192, 128, 64, 0):
        out |= fn((x >> shift) & M64) << shift
    return out


def chunks(x: int, width: int) -> list[int]:
    mask = (1 << width) - 1
    return [
        (x >> shift) & mask
        for shift in range(256 - width, -1, -width)
    ]


def unchunks(xs: list[int], width: int) -> int:
    out = 0
    for x in xs:
        out = (out << width) | x
    return out


def perm32(x: int) -> int:
    a1, b1, c1, d1, a0, b0, c0, d0 = chunks(x, 32)
    return unchunks([d1, a1, b1, c1, d0, a0, b0, c0], 32)


def perm64(x: int) -> int:
    a, b, c, d = chunks(x, 64)
    return unchunks([b, c, d, a], 64)


def swap64(x: int) -> int:
    a, b, c, d = chunks(x, 64)
    return unchunks([b, a, d, c], 64)


def swap128(x: int) -> int:
    a, b = chunks(x, 128)
    return unchunks([b, a], 128)


def lam(s: "State") -> "State":
    a0, a1, b0, b1, c0, c1 = s.as_tuple()
    b1 ^= perm32(c1)
    b0 ^= a1
    c0 ^= per_word(a0, lambda x: rol64(x, 29))
    b1 ^= per_word(a1, lambda x: rol64(x, 31))
    c1 ^= per_word(a0, lambda x: rol64(x, 13))
    c0 ^= b1
    a0 = perm64(a0)
    c1 ^= perm32(b1)
    a1 = swap128(a1)
    a0 ^= swap64(c0)
    a1 ^= perm32(b0)
    b1 ^= per_word(a0, lambda x: rol64(x, 7))
    c1 ^= per_word(a1, lambda x: ror64(x, 5))
    return State(a0, a1, b0, b1, c0, c1)


def chi_even(s: "State") -> "State":
    a0, a1, b0, b1, c0, c1 = s.as_tuple()
    return State(
        a0 ^ ((~b0 & M256) & c0),
        a1 ^ ((~b1 & M256) & c1),
        b0 ^ ((~c0 & M256) & a0),
        b1 ^ ((~c1 & M256) & a1),
        c0 ^ ((~a0 & M256) & b0),
        c1 ^ ((~a1 & M256) & b1),
    )


def chi_odd(s: "State") -> "State":
    a0, a1, b0, b1, c0, c1 = s.as_tuple()
    return State(
        a0 ^ ((~b1 & M256) & c1),
        a1 ^ ((~b0 & M256) & c0),
        b0 ^ ((~c0 & M256) & a1),
        b1 ^ ((~c1 & M256) & a0),
        c0 ^ ((~a1 & M256) & b0),
        c1 ^ ((~a0 & M256) & b1),
    )


def tau_even(s: "State") -> "State":
    a0, a1, b0, b1, c0, c1 = s.as_tuple()
    return State(c1, a0, a1, b0, b1, c0)


def tau_odd(s: "State") -> "State":
    a0, a1, b0, b1, c0, c1 = s.as_tuple()
    return State(a1, b0, b1, c0, c1, a0)


def round_constant(i: int) -> int:
    x = (
        0xDEADBEEF00000000
        ^ i
        ^ ((0x9E3779B97F4A7C15 * (i + 1)) & M64)
    ) & M64
    return x | (x << 64) | (x << 128) | (x << 192)


def one_round(s: "State", r: int, add_constant: bool = True) -> "State":
    s = lam(s)
    if add_constant:
        a0, a1, b0, b1, c0, c1 = s.as_tuple()
        s = State(a0 ^ round_constant(r), a1, b0, b1, c0, c1)
    s = chi_even(s) if r % 2 == 0 else chi_odd(s)
    s = tau_even(s) if (r // 3) % 2 == 0 else tau_odd(s)
    return s


def permutation(s: "State", rounds: int) -> "State":
    for r in range(rounds):
        s = one_round(s, r)
    return s


def rot_word_sym(s: "State", n: int) -> "State":
    return State(*(per_word(x, lambda y, n=n: rol64(y, n)) for x in s.as_tuple()))


def xor_state(x: "State", y: "State") -> "State":
    return State(*(a ^ b for a, b in zip(x.as_tuple(), y.as_tuple())))


def eq_state(x: "State", y: "State") -> bool:
    return x.as_tuple() == y.as_tuple()


@dataclass(frozen=True)
class State:
    a0: int
    a1: int
    b0: int
    b1: int
    c0: int
    c1: int

    def as_tuple(self) -> tuple[int, int, int, int, int, int]:
        return self.a0, self.a1, self.b0, self.b1, self.c0, self.c1

    def bits(self) -> str:
        return "".join(f"{x:0256b}" for x in self.as_tuple())

    def to_bits_int(self) -> int:
        return int(self.bits(), 2)

    @classmethod
    def zero(cls) -> "State":
        return cls(0, 0, 0, 0, 0, 0)

    @classmethod
    def random(cls, rng: random.Random) -> "State":
        return cls(*(rng.getrandbits(256) for _ in range(6)))

    @classmethod
    def from_bits(cls, bits: str) -> "State":
        if len(bits) != 1536 or set(bits) - {"0", "1"}:
            raise ValueError("State must be exactly 1536 bits")
        return cls(*(int(bits[i:i + 256], 2) for i in range(0, 1536, 256)))


def pad(message: bytes, rate: int) -> list[bytes]:
    bits = "".join(f"{b:08b}" for b in message)
    bits += "1"
    bits += "0" * ((-len(bits) - 1) % rate)
    bits += "1"
    if len(bits) % rate:
        raise AssertionError("bad CHIME padding")
    return [
        int(bits[i:i + rate], 2).to_bytes(rate // 8, "big")
        for i in range(0, len(bits), rate)
    ]


def chime512(message: bytes) -> bytes:
    s = State.zero()
    for block in pad(message, 512):
        m = int.from_bytes(block, "big")
        s = permutation(State(s.a0 ^ m, s.a1, s.b0, s.b1, s.c0, s.c1), 15)
    return (s.a0 << 256 | s.a1).to_bytes(64, "big")


def chime1024(message: bytes) -> bytes:
    s = State.zero()
    blocks = pad(message, 448)
    for block in blocks:
        m = int.from_bytes(block, "big")
        old = s
        injected = State(s.a0 ^ m, s.a1, s.b0, s.b1, s.c0, s.c1)
        p = permutation(injected, 20).as_tuple()
        # Feed forward the last 1088 bits of the pre-permutation state.
        ff = State(0, 0, p[2] ^ old.b0, p[3] ^ old.b1, p[4] ^ old.c0, p[5] ^ old.c1)
        s = State(p[0], p[1], ff.b0, ff.b1, ff.c0, ff.c1)
    a0, a1, b0, b1, c0, c1 = s.as_tuple()
    c1 ^= 1
    s = State(a0, a1, b0, b1, c0, c1)
    suffix = s.bits()[512:]
    return int(suffix, 2).to_bytes(128, "big")


def selftest() -> None:
    x0 = round_constant(0)
    assert all((x0 >> shift) & M64 == 0x409AC7567F4A7C15 for shift in (0, 64, 128, 192))
    for r in range(20):
        x = round_constant(r)
        assert x != 0
        assert x == round_constant(r)
    rng = random.Random(20261121)
    for _ in range(3):
        x = State.random(rng)
        assert eq_state(tau_odd(tau_even(x)), x)
        # The scalar model must produce a stable digest, not only round-trip.
        h = chime512(b"")
        assert hashlib.sha256(h).digest() == hashlib.sha256(chime512(b"")).digest()


if __name__ == "__main__":
    selftest()
    print("CHIME-512 empty:", chime512(b"").hex())
    print("CHIME-1024 empty:", chime1024(b"").hex())
