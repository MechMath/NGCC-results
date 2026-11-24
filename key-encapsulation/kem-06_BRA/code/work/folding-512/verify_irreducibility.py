#!/usr/bin/env python3
"""Exact irreducibility certificate for the BRA-512 quotient polynomial over F_2.

Polynomials are encoded as nonnegative integers: bit i is the coefficient of X^i.
No finite-field library is imported.  The checks implement the standard
Rabin irreducibility test.
"""

from math import gcd


P = (1 << 221) | (1 << 8) | (1 << 6) | (1 << 2) | 1


def degree(a: int) -> int:
    return a.bit_length() - 1


def poly_mod(a: int, modulus: int) -> int:
    dm = degree(modulus)
    while a and degree(a) >= dm:
        a ^= modulus << (degree(a) - dm)
    return a


def mul_mod(a: int, b: int, modulus: int) -> int:
    """Carry-less multiplication followed by exact polynomial reduction."""
    result = 0
    while b:
        if b & 1:
            result ^= a
        b >>= 1
        a <<= 1
    return poly_mod(result, modulus)


def square_mod(a: int, modulus: int) -> int:
    return mul_mod(a, a, modulus)


def frobenius_power(e: int) -> int:
    """Return X^(2^e) modulo P by e repeated squarings."""
    value = 0b10
    for _ in range(e):
        value = square_mod(value, P)
    return value


def poly_gcd(a: int, b: int) -> int:
    while b:
        a, b = b, poly_mod(a, b)
    return a


def main() -> None:
    assert P & 1
    assert gcd(P, 1 << 220) == 1  # P'(X)=X^220 and X does not divide P.

    r13 = frobenius_power(13)
    r17 = frobenius_power(17)
    r221 = frobenius_power(221)

    g13 = poly_gcd(P, r13 ^ 0b10)
    g17 = poly_gcd(P, r17 ^ 0b10)
    g221 = poly_gcd(P, r221 ^ 0b10)

    assert g13 == 1
    assert g17 == 1
    assert g221 == P
    assert r221 == 0b10

    print("P_hex =", hex(P))
    print("P_degree =", degree(P))
    print("P_derivative_gcd = 1")
    print("prime_divisors_221 = 13,17")
    print("R13 = X^(2^13) mod P =", hex(r13))
    print("R17 = X^(2^17) mod P =", hex(r17))
    print("R221 = X^(2^221) mod P =", hex(r221))
    print("gcd_X13 =", hex(g13))
    print("gcd_X17 =", hex(g17))
    print("gcd_X221_minus_X =", hex(g221))
    print("CONCLUSION: P is irreducible over F_2")


if __name__ == "__main__":
    main()
