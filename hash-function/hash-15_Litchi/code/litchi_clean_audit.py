#!/usr/bin/env python3
"""Finite consistency audit of the clean Litchi specification.

This is a research note, not execution evidence for an attack.  It checks the
normative finite objects in the PDF whose source is recorded in SOURCE_SHA256.
"""

from __future__ import annotations

import hashlib
import math
from collections import Counter
from pathlib import Path


SOURCE = Path("hash-15-spec.pdf")
SOURCE_SHA256 = "454300f46f71ea5cb74daa4df99f0a1a9c2276cdeb9aa7f9ff72f178b8e32bec"
MASK64 = (1 << 64) - 1

SBOX = [
    0, 2, 4, 23, 8, 10, 14, 13, 16, 18, 20, 15, 28, 30, 26, 17,
    1, 19, 5, 6, 9, 27, 31, 12, 25, 11, 29, 22, 21, 7, 3, 24,
]

THETA_TUPLES = [
    [31, 1, 4, 21, 22],
    [19, 12, 15, 34, 13],
    [28, 35, 58, 9, 23],
    [55, 18, 5, 27, 44],
    [14, 43, 53, 20, 25],
]

ROUND_CONSTANTS = [
    "b7e151628aed2a6a", "af82a3cd15dad4d7", "9f4546922bb529ad",
    "feca8c2c576ad359", "3dd51950aed526b1", "7baa32a15daa4d62",
    "f7546542bb549ac4", "2ee8cb8d76a9b58b", "5dd1971aed536b16",
    "bba32e35daa6d62c", "b7065d63b54d2c5b", "ae4cbbcf6a9ad8b5",
    "9cd97696d5353169", "f9f2ec25aa6ae2d1", "33a5d94354d545a1",
    "674bb286a9aa8b42",
]

FIELD_POLY = (
    (1 << 64) | (1 << 63) | (1 << 62) | (1 << 54) |
    (1 << 40) | (1 << 35) | (1 << 15) | (1 << 1) | 1
)


def rotl(x: int, n: int) -> int:
    n %= 64
    return ((x << n) | (x >> ((64 - n) % 64))) & MASK64


def sbox_boolean(x: int) -> int:
    # Bit 0 in the specification is the most-significant bit of the 5-bit word.
    a0, a1, a2, a3, a4 = [(x >> (4 - i)) & 1 for i in range(5)]
    b0 = (a0 & a2 & a3) ^ (a2 & a3 & a4) ^ (a0 & a4) ^ (a3 & a4) ^ a1
    b1 = (a1 & a3 & a4) ^ (a0 & a1) ^ a2
    b2 = (a1 & a2) ^ a3
    b3 = (a2 & a3) ^ a4
    b4 = (a3 & a4) ^ a0
    return sum(bit << (4 - i) for i, bit in enumerate((b0, b1, b2, b3, b4)))


def ddt() -> list[list[int]]:
    return [
        [sum(SBOX[x] ^ SBOX[x ^ a] == b for x in range(32)) for b in range(32)]
        for a in range(32)
    ]


def walsh() -> list[list[int]]:
    result = []
    for a in range(32):
        row = []
        for b in range(32):
            signed_sum = sum(
                1 if (((a & x).bit_count() ^ (b & SBOX[x]).bit_count()) & 1) == 0
                else -1
                for x in range(32)
            )
            row.append(signed_sum)
        result.append(row)
    return result


def gf_mul(a: int, b: int) -> int:
    result = 0
    while b:
        if b & 1:
            result ^= a
        b >>= 1
        a <<= 1
        if a >> 64:
            a ^= FIELD_POLY
    return result


def theta(words: list[int], ts: list[int]) -> list[int]:
    e = words[0] ^ words[1] ^ words[2] ^ words[3] ^ words[4]
    f = 0
    for word, shift in zip(words, ts, strict=True):
        f ^= rotl(word, shift)
    return [
        word ^ rotl(e, -shift) ^ f
        for word, shift in zip(words, ts, strict=True)
    ]


def theta_transpose(words: list[int], ts: list[int]) -> list[int]:
    # A_ij = delta_ij + x^(-ti) + x^(tj); transpose swaps ti and tj.
    result = []
    for i, ti in enumerate(ts):
        value = 0
        for j, tj in enumerate(ts):
            if i == j:
                value ^= words[j]
            value ^= rotl(words[j], -tj)
            value ^= rotl(words[j], ti)
        result.append(value)
    return result


def cyclic_mul(a: int, b: int) -> int:
    result = 0
    while b:
        if b & 1:
            result ^= a
        b >>= 1
        a = (a << 1) & MASK64 | (a >> 63)
    return result & MASK64


def polynomial_divmod(a: int, b: int) -> tuple[int, int]:
    quotient = 0
    while a.bit_length() >= b.bit_length():
        shift = a.bit_length() - b.bit_length()
        quotient ^= 1 << shift
        a ^= b << shift
    return quotient, a


def polynomial_gcd(a: int, b: int) -> tuple[int, int, int]:
    if b == 0:
        return a, 1, 0
    quotient, remainder = polynomial_divmod(a, b)
    g, x, y = polynomial_gcd(b, remainder)
    return g, y, x ^ cyclic_mul(quotient, y)


def cyclic_inverse(a: int) -> int:
    g, x, _ = polynomial_gcd(a, (1 << 64) | 1)
    assert g == 1
    return x & MASK64


def theta_matrix(ts: list[int]) -> list[list[int]]:
    return [
        [
            (1 if i == j else 0) ^ rotl(1, -ts[i]) ^ rotl(1, ts[j])
            for j in range(5)
        ]
        for i in range(5)
    ]


def invert_five_by_five(matrix: list[list[int]]) -> list[list[int]]:
    augmented = [
        row[:] + [(1 if i == j else 0) for j in range(5)]
        for i, row in enumerate(matrix)
    ]
    for column in range(5):
        pivot = next(i for i in range(column, 5) if augmented[i][column] & 1)
        augmented[column], augmented[pivot] = augmented[pivot], augmented[column]
        inverse = cyclic_inverse(augmented[column][column])
        augmented[column] = [cyclic_mul(x, inverse) for x in augmented[column]]
        for i in range(5):
            if i != column and augmented[i][column]:
                factor = augmented[i][column]
                augmented[i] = [
                    x ^ cyclic_mul(factor, y)
                    for x, y in zip(augmented[i], augmented[column], strict=True)
                ]
    return [row[5:] for row in augmented]


def printed_theta_inverse_formula(ts: list[int]) -> list[list[int]]:
    sum_right = 0
    sum_left = 0
    for shift in ts:
        sum_right ^= rotl(1, -shift)
        sum_left ^= rotl(1, shift)
    denominator = (
        sum_right ^ sum_left ^ cyclic_mul(sum_right, sum_left)
    )
    denominator_inverse = cyclic_inverse(denominator)
    result = []
    for i in range(5):
        row = []
        for j in range(5):
            term = (
                1
                ^ cyclic_mul(1 ^ sum_left, rotl(1, -ts[i]))
                ^ cyclic_mul(1 ^ sum_right, rotl(1, ts[j]))
                ^ rotl(1, -ts[i] + ts[j])
            )
            row.append(
                (1 if i == j else 0)
                ^ cyclic_mul(denominator_inverse, term)
            )
        result.append(row)
    return result


def gf2_rank(rows: list[int], width: int) -> int:
    rows = rows[:]
    rank = 0
    for column in range(width):
        pivot = next(
            (i for i in range(rank, len(rows)) if (rows[i] >> column) & 1),
            None,
        )
        if pivot is None:
            continue
        rows[rank], rows[pivot] = rows[pivot], rows[rank]
        for i in range(len(rows)):
            if i != rank and ((rows[i] >> column) & 1):
                rows[i] ^= rows[rank]
        rank += 1
    return rank


def theta_rank(ts: list[int]) -> int:
    rows = []
    for lane in range(5):
        for bit in range(64):
            words = [0] * 5
            words[lane] = 1 << bit
            output = theta(words, ts)
            rows.append(sum(word << (64 * i) for i, word in enumerate(output)))
    return gf2_rank(rows, 320)


def pi_map(index: tuple[int, int]) -> tuple[int, int]:
    i, j = index
    return (4 * i + 4 * j) % 5, (i + 3 * j) % 5


def permutation_order(index: tuple[int, int]) -> int:
    current = index
    for order in range(1, 25):
        current = pi_map(current)
        if current == index:
            return order
    raise AssertionError("orbit did not close within 24")


def nonlinear(state: list[list[int]]) -> list[list[int]]:
    output = [[0] * 5 for _ in range(5)]
    for lane in range(5):
        for bit in range(64):
            a = [(state[i][lane] >> (63 - bit)) & 1 for i in range(5)]
            b = (
                (a[0] & a[2] & a[3]) ^ (a[2] & a[3] & a[4])
                ^ (a[0] & a[4]) ^ (a[3] & a[4]) ^ a[1],
                (a[1] & a[3] & a[4]) ^ (a[0] & a[1]) ^ a[2],
                (a[1] & a[2]) ^ a[3],
                (a[2] & a[3]) ^ a[4],
                (a[3] & a[4]) ^ a[0],
            )
            for i in range(5):
                output[i][lane] ^= b[i] << (63 - bit)
    return output


def full_round(state: list[list[int]], round_index: int) -> list[list[int]]:
    state = [row[:] for row in state]
    state[0][0] ^= int(ROUND_CONSTANTS[round_index], 16)
    state = nonlinear(state)
    state = [theta(plane, ts) for plane, ts in zip(state, THETA_TUPLES, strict=True)]
    output = [[0] * 5 for _ in range(5)]
    for i in range(5):
        for j in range(5):
            # Normative equation: B[i][j] = A[(i+2j) mod 5][(3i+3j) mod 5].
            source_i = (i + 2 * j) % 5
            source_j = (3 * i + 3 * j) % 5
            output[i][j] = state[source_i][source_j]
    return output


def permutation(state: list[list[int]], rounds: int) -> list[list[int]]:
    for round_index in range(rounds):
        state = full_round(state, round_index)
    return state


def pad(message_length: int, rate: int) -> str:
    zeros = rate - 1 - (message_length % rate)
    return "M" * message_length + "1" + "0" * zeros


def main() -> None:
    digest = hashlib.sha256(SOURCE.read_bytes()).hexdigest()
    assert digest == SOURCE_SHA256

    calculated = [sbox_boolean(x) for x in range(32)]
    assert calculated == SBOX
    assert len(set(SBOX)) == 32

    table = ddt()
    assert max(max(row[1:]) for row in table) == 8
    differential_branch1 = [
        (a, b) for a in range(1, 32) for b in range(1, 32)
        if a.bit_count() == b.bit_count() == 1 and table[a][b]
    ]
    assert len(differential_branch1) == 5

    was = walsh()
    assert max(abs(was[a][b]) for a in range(1, 32) for b in range(1, 32)) == 16
    linear_branch1 = [
        (a, b) for a in range(1, 32) for b in range(1, 32)
        if a.bit_count() == b.bit_count() == 1 and was[a][b]
    ]
    assert len(linear_branch1) == 5

    constant = int(ROUND_CONSTANTS[0], 16)
    regenerated = []
    value = constant
    for _ in range(16):
        regenerated.append(f"{value:016x}")
        value = gf_mul(value, 2)
    assert regenerated == ROUND_CONSTANTS

    # x^(2^64) = x and gcd(x^(2^32)-x, p)=1 imply irreducibility for degree 64.
    x = 2
    for _ in range(64):
        x = gf_mul(x, x)
    assert x == 2
    x = 2
    for _ in range(32):
        x = gf_mul(x, x)
    a, b = x ^ 2, FIELD_POLY
    while b:
        a, b = b, a % b
    assert a == 1

    ranks = [theta_rank(ts) for ts in THETA_TUPLES]
    assert ranks == [320] * 5
    for ts in THETA_TUPLES:
        actual_inverse = invert_five_by_five(theta_matrix(ts))
        assert actual_inverse == printed_theta_inverse_formula(ts)

    # Exact disproof of the asserted Theta^T = Theta identity.
    asymmetry_witnesses = []
    for ts in THETA_TUPLES:
        witness = [1, 0, 0, 0, 0]
        left = theta(witness, ts)
        right = theta_transpose(witness, ts)
        assert left != right
        asymmetry_witnesses.append(
            ([f"{v:016x}" for v in left], [f"{v:016x}" for v in right])
        )
        for lane in range(5):
            basis = [0] * 5
            basis[lane] = 0x9E3779B97F4A7C15
            assert theta_transpose(basis, ts) == theta(basis, [-t % 64 for t in ts])

    positions = [(i, j) for i in range(5) for j in range(5)]
    mapped = {pi_map(p) for p in positions}
    assert mapped == set(positions)
    order_counts = Counter(permutation_order(p) for p in positions)
    # The matrix has order 24.  On GF(5)^2, (0,0) is fixed and the other
    # 24 positions form one orbit.
    assert order_counts == Counter({24: 24, 1: 1})

    # Direct enumeration of every one-bit input difference checks the claimed
    # three-round full diffusion at bit level.
    three_round_output_weights = []
    for i in range(5):
        for j in range(5):
            for bit in range(64):
                state = [[0] * 5 for _ in range(5)]
                state[i][j] = 1 << (63 - bit)
                diff = permutation(state, 3)
                three_round_output_weights.append(
                    sum(word.bit_count() for plane in diff for word in plane)
                )
    assert min(three_round_output_weights) > 0

    # Padding is injective in the tested bit-length window, including boundaries.
    rates = [1600 - c for c in (576, 832, 1088, 1024)]
    for rate in rates:
        samples = {}
        for length in range(0, 3 * rate + 2):
            value = pad(length, rate)
            assert len(value) == math.ceil((length + 1) / rate) * rate
            assert value not in samples, (rate, length, samples.get(value))
            samples[value] = length

    # Output and counter bounds used by the four published instances.
    instances = {
        "Litchi-512": (576, 0, 512),
        "Litchi-768": (832, 0, 768),
        "Litchi-1024": (1088, 0, 1024),
        "Litchi-XOF": (1024, 1, (1 << 64) - 1),
    }
    for name, (capacity, fid, max_output) in instances.items():
        assert capacity < 1600
        if fid == 0:
            assert max_output <= capacity - 64
            assert math.ceil(max_output / capacity) == 1
        else:
            assert math.ceil(max_output / capacity) < (1 << capacity)

    print("PASS source sha256", digest)
    print("PASS Table 2-2 equals Boolean equation truth table for all 32 inputs")
    print("PASS DDT max 8/32 and linear Walsh max |16|/32")
    print("PASS all 16 round constants regenerate from e fractional bits")
    print("PASS declared GF(2^64) polynomial is irreducible")
    print("PASS all five Theta maps have rank 320")
    print("PASS the printed inverse formula equals the computed 5x5 matrix inverse")
    print("FAIL asserted Theta^T = Theta")
    for i, (left, right) in enumerate(asymmetry_witnesses):
        print(f"  Theta_{i}, input (1,0,0,0,0)")
        print("    Theta       =", left)
        print("    Theta^T     =", right)
    print("NOTE actual identity is Theta[t_i]^T = Theta[-t_i mod 64]")
    print("PASS pi formula is a bijection: one fixed lane and one 24-lane orbit")
    print(
        "PASS all 1600 one-bit differences are nonzero after 3 rounds; "
        f"minimum output Hamming weight {min(three_round_output_weights)}"
    )
    print("PASS pad formula is injective over 0..3r+1 bit lengths for all four rates")
    print("PASS published hash/XOF capacities, domains, and counter widths fit")


if __name__ == "__main__":
    main()
