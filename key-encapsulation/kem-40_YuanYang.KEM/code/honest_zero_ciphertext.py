#!/usr/bin/env python3
"""Exact d=512 check for the honest zero-ciphertext KEM rejection witness.

This is auxiliary analysis, not execution evidence. It follows the literal
coefficient operations in Algorithms 3, 4, 6, 8, and 9 of the pinned
kem-40-spec.pdf.
"""

from __future__ import annotations

from math import floor


D = 512
M = D // 2
Q = 2689
K = 3


def mul_mod_cyclotomic(
    left: list[int], right: list[int], modulus: int | None = None
) -> list[int]:
    out = [0] * D
    for i, a in enumerate(left):
        if not a:
            continue
        for j, b in enumerate(right):
            if not b:
                continue
            index = i + j
            if index >= D:
                out[index - D] -= a * b
            else:
                out[index] += a * b
    if modulus is not None:
        out = [value % modulus for value in out]
    return out


def compress(value: int) -> int:
    return floor((value - 1 + K % 2) / K)


def main() -> None:
    zero = [0] * D
    one = [0] * D
    one[0] = 1
    p = [0] * D
    p[0] = p[M] = 1
    low_half = [1 if i < M // 2 else 0 for i in range(D)]

    # f=g=1 and f_2^{-1}=1. The honest stream is msg'=0 and s=e=0.
    m = zero
    s = zero
    e = zero
    public_key = one
    cbar = [
        (a + b + c) % Q
        for a, b, c in zip(
            mul_mod_cyclotomic(public_key, s, Q),
            e,
            m,
        )
    ]
    ciphertext_polynomial = [compress(value) for value in cbar]
    assert ciphertext_polynomial == zero

    # Algorithm 4, lines 1-3.
    bar_c = [(K * value) % Q for value in ciphertext_polynomial]
    bar_c_prime = mul_mod_cyclotomic(bar_c, p, Q)
    t: list[int] = []
    for i, value in enumerate(bar_c_prime):
        # The correction is low_half[i]/2. Keep the comparison integral.
        correction_twice = low_half[i]
        numerator_twice = 2 * value - correction_twice
        t.append(value - Q * floor(numerator_twice / (2 * Q)))
    assert t == [Q if i < M // 2 else 0 for i in range(D)]

    # Algorithm 6 modulo (p,2): quotient coordinates add their X^M mate.
    tbar = [(t[i] ^ t[i + M]) & 1 for i in range(M)]
    assert tbar == low_half[:M]
    low = tbar[: M // 2] + [0] * (M // 2)
    u = [a ^ b for a, b in zip(tbar, low)]
    assert not any(u)
    overflow = [0] * M

    # C=t-q*a and multiplication by f_2^{-1}=1 modulo p.
    recovered_quotient = [(a ^ b) for a, b in zip(tbar, overflow)]
    recovered_low = recovered_quotient[: M // 2]
    assert recovered_low == [1] * (M // 2)

    # The received tag is F(0); the decryption guess makes the re-encryption
    # tag F(S_rho1(0)) xor F(1) xor F(0). Choose a realization in which it
    # cannot coincide with F(0).
    f0 = 0xA5
    f1 = 0x5A
    freencrypt = 0xC3
    received_tag = f0
    guessed_message = f1 ^ f0
    reencrypt_tag = freencrypt ^ guessed_message
    assert reencrypt_tag != received_tag

    print("d, q, k:", D, Q, K)
    print("honest ciphertext polynomial weight:", sum(x != 0 for x in ciphertext_polynomial))
    print("line-3 t support:", sum(x != 0 for x in t))
    print("Algorithm-6 Hamming(u):", sum(u))
    print("recovered Low(m) weight:", sum(recovered_low))
    print("guessed external message:", guessed_message)
    print("re-encryption tag differs:", reencrypt_tag != received_tag)


if __name__ == "__main__":
    main()
