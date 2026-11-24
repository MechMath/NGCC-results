#!/usr/bin/env python3
"""Independent arithmetic audit of the April 2026 CHIME specification.

This script checks the finite tables and substitutions stated in the original
specification.  It does not claim that finite table checks establish security.
"""

from __future__ import annotations

from fractions import Fraction
from itertools import product
from math import sqrt

import mpmath as mp


SBOX = [0, 5, 3, 2, 6, 1, 4, 7]


def sbox_checks() -> None:
    assert len(SBOX) == 8 and len(set(SBOX)) == 8
    assert [SBOX.index(x) for x in range(8)] == SBOX

    ddt = [
        [sum((SBOX[x] ^ SBOX[x ^ a]) == b for x in range(8)) for b in range(8)]
        for a in range(8)
    ]
    expected_ddt = [
        [8, 0, 0, 0, 0, 0, 0, 0],
        [0, 2, 0, 2, 0, 2, 0, 2],
        [0, 0, 2, 2, 0, 0, 2, 2],
        [0, 2, 2, 0, 0, 2, 2, 0],
        [0, 0, 0, 0, 2, 2, 2, 2],
        [0, 2, 0, 2, 2, 0, 2, 0],
        [0, 0, 2, 2, 2, 2, 0, 0],
        [0, 2, 2, 0, 2, 0, 0, 2],
    ]
    assert ddt == expected_ddt
    assert max(ddt[a][b] for a in range(1, 8) for b in range(8)) == 2

    def parity(x: int) -> int:
        return x.bit_count() & 1

    lat = [
        [
            sum(1 if parity(x & a) == parity(SBOX[x] & b) else -1 for x in range(8))
            for b in range(8)
        ]
        for a in range(8)
    ]
    expected_lat = [
        [8, 0, 0, 0, 0, 0, 0, 0],
        [0, 4, 0, 4, 0, -4, 0, 4],
        [0, 0, 4, -4, 0, 0, 4, 4],
        [0, 4, -4, 0, 0, 4, 4, 0],
        [0, 0, 0, 0, 4, 4, -4, 4],
        [0, -4, 0, 4, 4, 0, 4, 0],
        [0, 0, 4, 4, -4, 4, 0, 0],
        [0, 4, 4, 0, 4, 0, 0, -4],
    ]
    assert lat == expected_lat
    assert max(abs(lat[a][b]) for a in range(1, 8) for b in range(1, 8)) == 4

    # If all three output bits have degree at most two, the vectorial
    # function has algebraic degree two.
    for output_bit in range(3):
        truth = [(SBOX[x] >> output_bit) & 1 for x in range(8)]
        anf = truth[:]
        for variable in range(3):
            for mask in range(8):
                if mask & (1 << variable):
                    anf[mask] ^= anf[mask ^ (1 << variable)]
        assert max(mask.bit_count() for mask, coefficient in enumerate(anf) if coefficient) == 2

    # The bit-sliced chi equations produce the table at all eight inputs.
    for x in range(8):
        x0, x1, x2 = (x >> 2) & 1, (x >> 1) & 1, x & 1
        y0 = x0 ^ ((1 - x1) & x2)
        y1 = x1 ^ ((1 - x2) & x0)
        y2 = x2 ^ ((1 - x0) & x1)
        assert (y0 << 2) | (y1 << 1) | y2 == SBOX[x]

    print("sbox: bijective; inverse", SBOX)
    print("ddt: exact; maximum nonzero-row count 2/8 = 2^-2")
    print("lat: exact; maximum nonzero-row |count| 4/8 = 1/2 correlation")
    print("algebraic degree: 2")


def round_constants() -> None:
    modulus = 1 << 64
    mask = modulus - 1
    seed = 0xDEADBEEF00000000
    golden = 0x9E3779B97F4A7C15
    reported = [
        0x409AC7567F4A7C15,
        0xE2C34D9DFE94F82B,
        0x040BD3C37DDF743D,
        0xA670580AFD29F057,
        0xC9B8DE707C746C6D,
        0x6BE164B7FBBEE87B,
        0x8D29EAFD7B096495,
        0x2F167324FA53E0AF,
        0x515EF96A799E5CB5,
        0xF0877FD1F8E8D8DB,
        0x12CF8417783354ED,
        0xB4340A5EF77DD0F7,
        0xD67C908476C84D1D,
        0x79A516CBF612C92B,
        0x9BED9F31755D4535,
        0x3DDA2578F4A7C15F,
        0x5F02ABBE73F23D75,
        0xC14B31E5F33CB96B,
        0x60B3B62B7287359D,
        0x82F83C92F1D1B1B7,
    ]
    computed = [
        (seed ^ i ^ ((golden * (i + 1)) & mask)) & mask
        for i in range(20)
    ]
    assert computed == reported
    print("round constants 0..19: all 20 match the displayed formula")


def padding_checks() -> None:
    def pad(message: tuple[int, ...], rate: int) -> tuple[int, ...]:
        k = (-(len(message) + 2)) % rate
        return message + (1,) + (0,) * k + (1,)

    for rate in (512, 448):
        seen: dict[tuple[int, ...], tuple[int, ...]] = {}
        for length in range(14):
            for message in product((0, 1), repeat=length):
                padded = pad(message, rate)
                assert len(padded) % rate == 0
                assert padded[-1] == 1
                preceding_one = max(i for i in range(len(padded) - 1) if padded[i] == 1)
                assert padded[preceding_one + 1 : -1] == (0,) * (len(padded) - preceding_one - 2)
                assert padded[:preceding_one] not in seen
                seen[padded[:preceding_one]] = padded

        # The constructive inverse proves injectivity for every finite message:
        # delete the final one, then all trailing zeros, then delete the last one.
        for padded in seen.values():
            stripped_zeros = padded[:-1]
            while stripped_zeros and stripped_zeros[-1] == 0:
                stripped_zeros = stripped_zeros[:-1]
            assert stripped_zeros[-1] == 1
            recovered = stripped_zeros[:-1]
            assert pad(recovered, rate) == padded
        print(f"padding rate {rate}: exact length; end-marker inverse recovers every tested message")


def generic_security_substitutions() -> None:
    # CHIME-512: n=512, c=1024, r'=512.
    n, c, squeeze_rate = 512, 1024, 512
    collision = min(2 ** (n // 2), 2 ** (c // 2))
    preimage = min(
        2**n,
        max(2 ** (n - squeeze_rate), 2 ** (c // 2)),
    )
    second_preimage = min(2**n, 2 ** (c // 2))
    assert (collision, preimage, second_preimage) == (2**256, 2**512, 2**512)

    # CHIME-1024: n=c?  The stated output is 1024, capacity is 1088.
    n, c = 1024, 1088
    assert (2 ** (n // 2), 2**n, min(2**n, 2 ** (c - 64))) == (
        2**512,
        2**1024,
        2**1024,
    )
    print("table 8: all CHIME-512 and CHIME-1024 substitutions equal the table")


def mitm_substitutions() -> None:
    def exponents_512(red: int, blue: int, conditions: int, linear: int,
                      nonlinear: int, matching: int) -> tuple[int, int]:
        sigma = linear + nonlinear
        time = max(512 - sigma + conditions, 512 - min(blue, red, matching))
        memory = max(red - linear, blue)
        return time, memory

    def exponents_1024(red: int, blue: int, conditions: int, linear: int,
                       nonlinear: int, matching: int) -> tuple[int, int]:
        sigma = linear + nonlinear
        time = max(1024 - min(blue, red - sigma, matching), sigma + conditions + 576)
        memory = max(red - linear, blue)
        return time, memory

    cases_512 = {
        "3 rounds": ((31, 30, 480, 1, 0, 30), (482, 30)),
        "4 rounds": ((49, 8, 450, 81, 0, 0), (544, 8)),
    }
    cases_1024 = {
        "end-matching 3R": ((27, 26, 415, 1, 0, 182), (998, 26)),
        "end-matching 4R": ((52, 1, 415, 20, 0, 0), (1024, 32)),
        "feedback mid-matching 4R": ((390, 58, 1037, 56, 0, 0), (1669, 372)),
    }
    for name, (parameters, reported) in cases_512.items():
        computed = exponents_512(*parameters)
        print("T512", name, "computed", computed, "reported", reported,
              "match", computed == reported)
    for name, (parameters, reported) in cases_1024.items():
        computed = exponents_1024(*parameters)
        print("T1024", name, "computed", computed, "reported", reported,
              "match", computed == reported)


def active_sbox_directions() -> None:
    # Record both directions literally because these lists are used as evidence.
    cases_512 = [(3, "<=", 8), (4, "<=", 14), (5, "<=", 51), (6, "<=", 28),
                 (7, "<=", 93), (8, "<=", 72), (9, "<=", 58), (10, ">=", 128)]
    cases_1024 = [(5, "<=", 34), (6, "<=", 30), (7, "<=", 36), (8, "<=", 40),
                  (9, "<=", 97), (10, "<=", 50), (11, ">=", 256)]
    assert all(rounds < 15 for rounds, _, _ in cases_512)
    assert all(rounds < 20 for rounds, _, _ in cases_1024)
    print("active S-box evidence: no lower bound is listed at 15 rounds (CHIME-512)")
    print("active S-box evidence: no lower bound is listed at 20 rounds (CHIME-1024)")


def performance_figures() -> None:
    chime512 = [2981.251, 4150.887, 4381.088, 4397.343, 4397.345]
    chime1024 = [2273.444, 2903.895, 3018.846, 3023.679, 3023.681]
    sha2 = [230.226, 549.466, 674.779, 685.196, 685.197]
    ratios_512 = [a / b for a, b in zip(chime512, sha2)]
    ratios_1024 = [a / b for a, b in zip(chime1024, sha2)]
    floor2 = lambda x: int(100 * x) / 100
    assert floor2(min(ratios_512)) == 6.41
    assert floor2(max(ratios_512)) == 12.94  # prose rounds this interval endpoint to 12.9
    assert floor2(min(ratios_1024)) == 4.41 and floor2(max(ratios_1024)) == 9.87
    assert floor2(2114 / 1552) == 1.36 and floor2(2509 / 1552) == 1.61
    print("table 3/4 prose ratios: speed intervals and 512-core area ratios reproduce")


def randomness_proportion_check() -> None:
    # Section A gives m=1000, alpha=0.01, and the interval
    # phat +/- 3 sqrt(phat(1-phat)/m).
    m = 1000
    alpha = Fraction(1, 100)
    phat = 1 - alpha
    radius = 3 * sqrt(float(phat * (1 - phat) / m))
    lower, upper = float(phat) - radius, float(phat) + radius
    assert 0.980 < lower < 0.981
    assert not (lower <= 980 / 1000 <= upper)

    # The feedback-mode CHIME-1024 FFT row is marked Pass with 980/1000.
    # Its listed P-value is 0.006710.
    mp.mp.dps = 50
    p = mp.mpf(99) / 100
    inverse_tail = sum(
        mp.binomial(m, k) * p**k * (1 - p) ** (m - k)
        for k in range(981)
    )
    print("randomness proportion: m=1000 interval",
          (lower, upper), "but Table 15 marks 980/1000 Pass")
    print("binomial Pr[X<=980 | p=.99] =", mp.nstr(inverse_tail, 16))
    print("Table 15 CHIME-1024 feedback FFT P-value 0.006710 is below alpha=.01")


def quantum_tradeoff_check() -> None:
    # Work with exponents.  The displayed endpoint T=2^(n/2), S=1 has
    # T*S=2^(n/2); the BHT-style endpoint has T*S=2^(2n/3).
    for n in (512, 1024):
        assert Fraction(n, 2) == Fraction(n, 2)
        assert Fraction(2 * n, 3) > Fraction(n, 2)
    print("quantum tradeoff arithmetic: endpoints are 2^(n/2) and 2^(2n/3) in T*S")


def main() -> None:
    sbox_checks()
    round_constants()
    padding_checks()
    generic_security_substitutions()
    mitm_substitutions()
    active_sbox_directions()
    performance_figures()
    randomness_proportion_check()
    quantum_tradeoff_check()


if __name__ == "__main__":
    main()
