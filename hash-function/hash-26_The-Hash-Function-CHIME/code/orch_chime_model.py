#!/usr/bin/env python3
"""Independent integer model of the April 2026 CHIME specification.

Bit position 0 is the least significant bit of the Python integer.  A 256-bit
state array therefore stores word 0 in bits 0..63, word 1 in bits 64..127,
and so on.  The model is intended for structural experiments, not as official
test-vector evidence.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

MASK64 = (1 << 64) - 1
MASK256 = (1 << 256) - 1

SBOX = (0, 5, 3, 2, 6, 1, 4, 7)


def words64(x: int) -> list[int]:
    """Return words in integer significance order, for word-local rotations."""
    return [(x >> (64 * i)) & MASK64 for i in range(4)]


def pack64(ws: Iterable[int]) -> int:
    out = 0
    for i, word in enumerate(ws):
        out |= (word & MASK64) << (64 * i)
    return out


def words64_hi(x: int) -> list[int]:
    """Return [a,b,c,d] in the specification's left-to-right order."""
    return [(x >> (64 * i)) & MASK64 for i in (3, 2, 1, 0)]


def pack64_hi(ws: Iterable[int]) -> int:
    out = 0
    for word, shift in zip(ws, (192, 128, 64, 0)):
        out |= (word & MASK64) << shift
    return out


def rol64_words(x: int, n: int) -> int:
    n %= 64
    return pack64(((w << n) | (w >> (64 - n))) & MASK64 for w in words64(x))


def ror64_words(x: int, n: int) -> int:
    return rol64_words(x, -n)


def shl64_words(x: int, n: int) -> int:
    return pack64((w << n) & MASK64 for w in words64(x))


def shr64_words(x: int, n: int) -> int:
    return pack64(w >> n for w in words64(x))


def pi_perm64(x: int) -> int:
    a, b, c, d = words64_hi(x)
    return pack64_hi((b, c, d, a))


def pi_swap64(x: int) -> int:
    a, b, c, d = words64_hi(x)
    return pack64_hi((b, a, d, c))


def pi_swap128(x: int) -> int:
    a, b, c, d = words64_hi(x)
    return pack64_hi((c, d, a, b))


def pi_perm32(x: int) -> int:
    words = [
        (x >> (32 * i)) & ((1 << 32) - 1) for i in (7, 6, 5, 4, 3, 2, 1, 0)
    ]
    a1, b1, c1, d1, a0, b0, c0, d0 = words
    new = (d1, a1, b1, c1, d0, a0, b0, c0)
    return sum(word << (32 * shift) for shift, word in zip((7, 6, 5, 4, 3, 2, 1, 0), new))


def linear_layer(state: list[int]) -> list[int]:
    a0, a1, b0, b1, c0, c1 = state
    b1 ^= pi_perm32(c1)
    b0 ^= a1
    c0 ^= rol64_words(a0, 29)
    b1 ^= rol64_words(a1, 31)
    c1 ^= rol64_words(a0, 13)
    c0 ^= b1
    a0 = pi_perm64(a0)
    c1 ^= pi_perm32(b1)
    a1 = pi_swap128(a1)
    a0 ^= pi_swap64(c0)
    a1 ^= pi_perm32(b0)
    # The rendered page and font encoding distinguish the circular-left
    # glyphs in the first three terms from the ordinary shift used here.
    b1 ^= shl64_words(a0, 7)
    c1 ^= shr64_words(a1, 5)
    return [x & MASK256 for x in (a0, a1, b0, b1, c0, c1)]


def chi_layer(state: list[int], round_index: int) -> list[int]:
    a0, a1, b0, b1, c0, c1 = state
    if round_index % 2 == 0:
        return [
            a0 ^ ((~b0) & c0),
            a1 ^ ((~b1) & c1),
            b0 ^ ((~c0) & a0),
            b1 ^ ((~c1) & a1),
            c0 ^ ((~a0) & b0),
            c1 ^ ((~a1) & b1),
        ]
    return [
        a0 ^ ((~b1) & c1),
        a1 ^ ((~b0) & c0),
        b0 ^ ((~c0) & a1),
        b1 ^ ((~c1) & a0),
        c0 ^ ((~a1) & b0),
        c1 ^ ((~a0) & b1),
    ]


def tau_layer(state: list[int], round_index: int) -> list[int]:
    a0, a1, b0, b1, c0, c1 = state
    if (round_index // 3) % 2 == 0:
        return [c1, a0, a1, b0, b1, c0]
    return [a1, b0, b1, c0, c1, a0]


def round_constant(i: int) -> int:
    """The 64-bit Xi from section 3.2."""
    return (
        0xDEADBEEF00000000
        ^ i
        ^ ((0x9E3779B97F4A7C15 * (i + 1)) & MASK64)
    ) & MASK64


def round_function(state: list[int], round_index: int) -> list[int]:
    state = linear_layer(state)
    x = round_constant(round_index)
    state[0] ^= x * sum(1 << (64 * i) for i in range(4))
    state = chi_layer(state, round_index)
    state = tau_layer(state, round_index)
    return [a & MASK256 for a in state]


def permutation(state: list[int], rounds: int) -> list[int]:
    for r in range(rounds):
        state = round_function(state, r)
    return state


def bits_to_int(bits: str) -> int:
    """Map the literal specification bit string to our bit-0 integer order."""
    out = 0
    for i, bit in enumerate(reversed(bits)):
        if bit not in "01":
            raise ValueError("bits must contain only 0 and 1")
        out |= (bit == "1") << i
    return out


def int_bits(x: int, n: int) -> str:
    return "".join(str((x >> i) & 1) for i in range(n - 1, -1, -1))


def state_to_bits(state: list[int]) -> str:
    return "".join(int_bits(a, 256) for a in state)


def bits_to_state(bits: str) -> list[int]:
    if len(bits) != 1536:
        raise ValueError("state must contain exactly 1536 bits")
    return [bits_to_int(bits[i : i + 256]) for i in range(0, 1536, 256)]


def state_xor(left: list[int], right: list[int]) -> list[int]:
    return [x ^ y for x, y in zip(left, right)]


def linear_rank() -> int:
    """GF(2) rank of lambda, useful for convention and kernel checks."""
    columns = []
    for i in range(1536):
        state = [0] * 6
        state[i // 256] |= 1 << (i % 256)
        image = linear_layer(state)
        columns.append(sum(value << (256 * j) for j, value in enumerate(image)))
    pivots: dict[int, int] = {}
    for value in columns:
        while value:
            pivot = value.bit_length() - 1
            if pivot in pivots:
                value ^= pivots[pivot]
            else:
                pivots[pivot] = value
                break
    return len(pivots)


def xor_prefix_bits(state: list[int], value: int, width: int) -> list[int]:
    """XOR a big-endian bit string of `width` bits into the state prefix."""
    out = list(state)
    for i in range(min(width, 1536)):
        if (value >> (width - 1 - i)) & 1:
            out[i // 256] ^= 1 << (255 - i % 256)
    return out


def pad(message_bits: str, rate: int) -> str:
    zeroes = (-len(message_bits) - 2) % rate
    return message_bits + "1" + "0" * zeroes + "1"


@dataclass(frozen=True)
class Profile:
    name: str
    rate: int
    capacity: int
    rounds: int

    @property
    def block_bits(self) -> int:
        return self.rate + self.capacity


CHIME512 = Profile("CHIME-512", 512, 1024, 15)
CHIME1024 = Profile("CHIME-1024", 448, 1088, 20)


def chime(message_bits: str, profile: Profile) -> str:
    padded = pad(message_bits, profile.rate)
    if len(padded) % profile.rate:
        raise AssertionError("padding did not reach the rate")
    state = [0] * 6
    for offset in range(0, len(padded), profile.rate):
        block = padded[offset : offset + profile.rate]
        rate_part = bits_to_int(block)
        state = xor_prefix_bits(state, rate_part, profile.rate)
        old_capacity = [0] * 6
        # The capacity starts at bit 448 for CHIME-1024, so it crosses A1/B0.
        capacity_text = state_to_bits(state)[profile.rate :]
        cap_int = bits_to_int(capacity_text)
        for i in range(profile.capacity):
            global_pos = profile.rate + i
            value = (cap_int >> (profile.capacity - 1 - i)) & 1
            old_capacity[global_pos // 256] |= value << (255 - global_pos % 256)
        state = permutation(state, profile.rounds)
        if profile.name == "CHIME-1024":
            state = state_xor(state, old_capacity)
    if profile.name == "CHIME-1024":
        state[5] ^= 1
        final_bits = state_to_bits(state)
        return final_bits[-profile.capacity + 64 :]
    return state_to_bits(state)[:512]


def public_selftests() -> None:
    assert len(set(SBOX)) == 8
    assert linear_rank() == 1536
    assert round_constant(0) == 0x409AC7567F4A7C15
    assert round_constant(19) == 0x82F83C92F1D1B1B7


if __name__ == "__main__":
    public_selftests()
    print("round constants and primitive model self-tests passed")
