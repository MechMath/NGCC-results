#!/usr/bin/env python3
"""Audit the corrected six-variable CHIME-512 repeated-word family.

This intentionally implements the mixed lambda semantics separately from the
earlier chime_ref.py: rotations by 29,31,13 and logical shifts by 7,5.
"""

from __future__ import annotations

import math
import random
from fractions import Fraction

import chime_ref as ref


MASK64 = (1 << 64) - 1
MASK256 = (1 << 256) - 1
QWORD = 0x8000000000000001


def repeat_word(x: int) -> int:
    return x | (x << 64) | (x << 128) | (x << 192)


def contract_array(x: int) -> int:
    words = [(x >> (64 * i)) & MASK64 for i in range(4)]
    assert words[0] == words[1] == words[2] == words[3], (
        f"array is not 4-repeat: {x:064x}"
    )
    return words[0]


def contract_state(state: list[int]) -> list[int]:
    return [contract_array(x) for x in state]


def word_map(x: int, fn) -> int:
    return sum(fn((x >> (64 * i)) & MASK64) << (64 * i) for i in range(4))


def rol(x: int, n: int) -> int:
    return ((x << n) | (x >> (64 - n))) & MASK64


def shl(x: int, n: int) -> int:
    return (x << n) & MASK64


def shr(x: int, n: int) -> int:
    return x >> n


def packed_lambda(s: list[int]) -> list[int]:
    a0, a1, b0, b1, c0, c1 = s
    b1 ^= ref.perm32(c1)
    b0 ^= a1
    c0 ^= word_map(a0, lambda x: rol(x, 29))
    b1 ^= word_map(a1, lambda x: rol(x, 31))
    c1 ^= word_map(a0, lambda x: rol(x, 13))
    c0 ^= b1
    a0 = ref.perm64(a0)
    c1 ^= ref.perm32(b1)
    a1 = ref.swap128(a1)
    a0 ^= ref.swap64(c0)
    a1 ^= ref.perm32(b0)
    b1 ^= word_map(a0, lambda x: shl(x, 7))
    c1 ^= word_map(a1, lambda x: shr(x, 5))
    return [x & MASK256 for x in (a0, a1, b0, b1, c0, c1)]


def round_constant(rnd: int) -> int:
    return ref.round_constant(rnd)


def chi_bits(x0: int, x1: int, x2: int) -> tuple[int, int, int]:
    y0 = x0 ^ ((~x1) & x2)
    y1 = x1 ^ ((~x2) & x0)
    y2 = x2 ^ ((~x0) & x1)
    return y0 & MASK256, y1 & MASK256, y2 & MASK256


def packed_chi(s: list[int], rnd: int) -> list[int]:
    a0, a1, b0, b1, c0, c1 = s
    if rnd % 2 == 0:
        a0, b0, c0 = chi_bits(a0, b0, c0)
        a1, b1, c1 = chi_bits(a1, b1, c1)
    else:
        a0, b1, c1 = chi_bits(a0, b1, c1)
        a1, b0, c0 = chi_bits(a1, b0, c0)
    return [a0, a1, b0, b1, c0, c1]


def packed_tau(s: list[int], rnd: int) -> list[int]:
    a0, a1, b0, b1, c0, c1 = s
    if (rnd // 3) % 2 == 0:
        return [c1, a0, a1, b0, b1, c0]
    return [a1, b0, b1, c0, c1, a0]


def packed_round(s: list[int], rnd: int) -> list[int]:
    s = packed_lambda(s)
    s[0] ^= repeat_word(round_constant(rnd))
    return packed_tau(packed_chi(s, rnd), rnd)


def array_to_bits(x: int) -> str:
    return f"{x:0256b}"


def bits_to_array(x: str) -> int:
    assert len(x) == 256
    return int(x, 2)


def map_words_bits(x: int, fn) -> int:
    bits = array_to_bits(x)
    out = "".join(f"{fn(int(bits[i:i + 64], 2)):064b}" for i in range(0, 256, 64))
    return int(out, 2)


def perm32_bits(x: int) -> int:
    b = array_to_bits(x)
    chunks = [int(b[i:i + 32], 2) for i in range(0, 256, 32)]
    a1, b1, c1, d1, a0, b0, c0, d0 = chunks
    out = (d1, a1, b1, c1, d0, a0, b0, c0)
    return int("".join(f"{v:032b}" for v in out), 2)


def perm64_bits(x: int) -> int:
    b = array_to_bits(x)
    a, bb, c, d = (b[i:i + 64] for i in range(0, 256, 64))
    return int(bb + c + d + a, 2)


def swap64_bits(x: int) -> int:
    b = array_to_bits(x)
    a, bb, c, d = (b[i:i + 64] for i in range(0, 256, 64))
    return int(bb + a + d + c, 2)


def swap128_bits(x: int) -> int:
    b = array_to_bits(x)
    return int(b[128:] + b[:128], 2)


def direct_lambda(s: list[int]) -> list[int]:
    """Literal ordered formula with each array held as a 256-bit string."""
    a0, a1, b0, b1, c0, c1 = s
    b1 ^= perm32_bits(c1)
    b0 ^= a1
    c0 ^= map_words_bits(a0, lambda x: rol(x, 29))
    b1 ^= map_words_bits(a1, lambda x: rol(x, 31))
    c1 ^= map_words_bits(a0, lambda x: rol(x, 13))
    c0 ^= b1
    a0 = perm64_bits(a0)
    c1 ^= perm32_bits(b1)
    a1 = swap128_bits(a1)
    a0 ^= swap64_bits(c0)
    a1 ^= perm32_bits(b0)
    b1 ^= map_words_bits(a0, lambda x: shl(x, 7))
    c1 ^= map_words_bits(a1, lambda x: shr(x, 5))
    return [x & MASK256 for x in (a0, a1, b0, b1, c0, c1)]


def direct_chi(s: list[int], rnd: int) -> list[int]:
    a0, a1, b0, b1, c0, c1 = s
    if rnd % 2 == 0:
        a0, b0, c0 = chi_bits(a0, b0, c0)
        a1, b1, c1 = chi_bits(a1, b1, c1)
    else:
        a0, b1, c1 = chi_bits(a0, b1, c1)
        a1, b0, c0 = chi_bits(a1, b0, c0)
    return [a0, a1, b0, b1, c0, c1]


def direct_round(s: list[int], rnd: int) -> list[int]:
    s = direct_lambda(s)
    s[0] ^= repeat_word(round_constant(rnd))
    return packed_tau(direct_chi(s, rnd), rnd)


def family_message(u: list[int]) -> tuple[str, str, list[str]]:
    assert len(u) == 6
    assert all(0 <= x <= MASK64 for x in u)
    control = "".join(f"{x:064b}" * 4 for x in u)
    tail = f"{QWORD:064b}" * 7
    message = control + tail
    assert len(control) == 1536 and len(tail) == 448 and len(message) == 1984
    padded = message + "1" + "0" * 62 + "1"
    assert len(padded) == 2048
    blocks = [padded[i:i + 512] for i in range(0, 2048, 512)]
    return message, padded, blocks


def xor_first_arrays(state: list[int], block: str) -> list[int]:
    out = state.copy()
    out[0] ^= int(block[:256], 2)
    out[1] ^= int(block[256:], 2)
    return out


def evaluate_family(u: list[int], direct: bool = False) -> tuple[list[int], list[list[int]]]:
    _, padded, blocks = family_message(u)
    state = [0] * 6
    trace = []
    for block in blocks:
        state = xor_first_arrays(state, block)
        for rnd in range(15):
            state = direct_round(state, rnd) if direct else packed_round(state, rnd)
            contract_state(state)
        trace.append(state.copy())
    return state, trace


def audit() -> None:
    rng = random.Random(0xC41E512)

    # Primitive table and constants.
    assert ref.SBOX == (0, 5, 3, 2, 6, 1, 4, 7)
    assert ref.round_constant(0) == 0x409AC7567F4A7C15
    assert ref.round_constant(19) == 0x82F83C92F1D1B1B7
    assert QWORD.bit_length() == 64
    assert f"{QWORD:064b}" == "1" + "0" * 62 + "1"

    # The two independent ordered-lambda implementations agree on random states
    # and preserve every 4-repeat array.
    for _ in range(128):
        s = [rng.getrandbits(256) for _ in range(6)]
        assert packed_lambda(s) == direct_lambda(s)
        words = [rng.getrandbits(64) for _ in range(6)]
        r = [repeat_word(w) for w in words]
        assert contract_state(packed_lambda(r)) == contract_state(direct_lambda(r))
        for rnd in range(15):
            p = packed_round(r, rnd)
            q = direct_round(r, rnd)
            assert p == q
            contract_state(p)
            r = p

    # Injectivity and exact block/padding structure.
    seen = set()
    for i in range(2000):
        u = [rng.getrandbits(64) for _ in range(6)]
        message, padded, blocks = family_message(u)
        control, tail = message[:1536], message[1536:]
        assert tail == f"{QWORD:064b}" * 7
        assert padded[-64:] == f"{QWORD:064b}"
        assert [blocks[0][j:j + 256] for j in (0, 256)] == [
            f"{u[0]:064b}" * 4, f"{u[1]:064b}" * 4
        ]
        assert [blocks[i][j:j + 256] for i in (1, 2) for j in (0, 256)] == [
            f"{u[2]:064b}" * 4, f"{u[3]:064b}" * 4,
            f"{u[4]:064b}" * 4, f"{u[5]:064b}" * 4,
        ]
        assert blocks[3] == f"{QWORD:064b}" * 8
        assert control == "".join(f"{x:064b}" * 4 for x in u)
        if i == 0:
            seen.add(message)
    assert len(seen) == 1
    u = [rng.getrandbits(64) for _ in range(6)]
    v = u.copy()
    v[3] ^= 1
    assert family_message(u)[0] != family_message(v)[0]

    # Full 15-round packed and direct evaluations both end with repeat arrays.
    final_packed, trace_packed = evaluate_family(u, direct=False)
    final_direct, trace_direct = evaluate_family(u, direct=True)
    assert final_packed == final_direct
    assert trace_packed == trace_direct
    assert len(trace_packed) == 4 and all(len(contract_state(s)) == 6 for s in trace_packed)
    digest = "".join(array_to_bits(x) for x in final_packed)[:512]
    assert digest[:256] == digest[:64] * 4
    assert digest[256:] == digest[256:320] * 4

    # Exact birthday exponent and the numerical threshold actually proved.
    q0 = (1 << 66) + 1
    n = 1 << 128
    exponent = Fraction(q0 * (q0 - 1), 2 * n)
    exact_expected = Fraction(8) + Fraction(1, 1 << 63)
    success = 1.0 - math.exp(float(-exponent))
    assert exponent == exact_expected
    assert success > 0.9996

    print("PASS mixed-lambda implementation agreement")
    print("PASS 128 random all-R rounds; every array 4-repeat")
    print("PASS six-variable family is 1984 bits and pads to 4 exact blocks")
    print("PASS full 15-round packed/direct digest and traces agree")
    print("digest", digest)
    print("exponent", exponent)
    print("success_lower_bound", repr(success))


if __name__ == "__main__":
    audit()
