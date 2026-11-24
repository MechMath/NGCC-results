#!/usr/bin/env python3
"""Reproduce the Algorithm 6 ambiguity at the original d=512 profile.

This is an auxiliary analysis script, not execution evidence for the graph.
All polynomial arithmetic is exact.
"""

from __future__ import annotations


def trim(a: list[int]) -> list[int]:
    while len(a) > 1 and a[-1] == 0:
        a.pop()
    return a


def poly_mod_xm_minus_one(a: list[int], m: int) -> list[int]:
    out = [0] * m
    for i, value in enumerate(a):
        out[i % m] ^= value & 1
    return out


def poly_mul_mod(a: list[int], b: list[int], m: int) -> list[int]:
    out = [0] * m
    for i, av in enumerate(a):
        if av & 1:
            for j, bv in enumerate(b):
                if bv & 1:
                    out[(i + j) % m] ^= 1
    return out


def poly_divmod(a: list[int], b: list[int], q: int) -> tuple[list[int], list[int]]:
    a = trim(a[:])
    b = trim(b[:])
    inv_lead = pow(b[-1], -1, q)
    quotient = [0] * max(1, len(a) - len(b) + 1)
    for i in range(len(a) - 1, len(b) - 2, -1):
        coefficient = a[i] * inv_lead % q
        quotient[i - len(b) + 1] = coefficient
        if coefficient:
            for j, value in enumerate(b):
                a[i - len(b) + 1 + j] = (
                    a[i - len(b) + 1 + j] - coefficient * value
                ) % q
    return quotient, trim(a)


def poly_mul_mod2(a: list[int], b: list[int]) -> list[int]:
    out = [0] * (len(a) + len(b) - 1)
    for i, av in enumerate(a):
        if av & 1:
            for j, bv in enumerate(b):
                out[i + j] ^= bv & 1
    return trim(out)


def poly_inv_mod2(a: list[int], modulus: list[int]) -> list[int]:
    """Extended Euclid over F_2, returning a^{-1} modulo modulus."""
    old_r, r = trim(modulus[:]), trim(a[:])
    old_s, s = [0], [1]
    while not (len(r) == 1 and r[0] == 0):
        quotient, remainder = poly_divmod(old_r, r, 2)
        old_r, r = r, remainder
        product = poly_mul_mod2(quotient, s)
        old_s, s = s, trim(
            [
                (old_s[i] if i < len(old_s) else 0)
                ^ (product[i] if i < len(product) else 0)
                for i in range(max(len(old_s), len(product)))
            ]
        )
    assert old_r == [1]
    return old_s


def poly_gcd(a: list[int], b: list[int], q: int) -> list[int]:
    a = trim(a[:])
    b = trim(b[:])
    while not (len(b) == 1 and b[0] == 0):
        _, remainder = poly_divmod(a, b, q)
        a, b = b, remainder
    inverse = pow(a[-1], -1, q)
    return [value * inverse % q for value in a]


def poly_mul_mod_q(a: list[int], b: list[int], q: int) -> list[int]:
    out = [0] * (len(a) + len(b) - 1)
    for i, av in enumerate(a):
        for j, bv in enumerate(b):
            out[i + j] = (out[i + j] + av * bv) % q
    return trim(out)


def poly_inv_mod_q(a: list[int], modulus: list[int], q: int) -> list[int]:
    old_r, r = trim(modulus[:]), trim(a[:])
    old_s, s = [0], [1]
    while not (len(r) == 1 and r[0] == 0):
        quotient, remainder = poly_divmod(old_r, r, q)
        old_r, r = r, remainder
        product = poly_mul_mod_q(quotient, s, q)
        old_s, s = s, [
            ((old_s[i] if i < len(old_s) else 0)
             - (product[i] if i < len(product) else 0)) % q
            for i in range(max(len(old_s), len(product)))
        ]
        trim(old_s)
        trim(s)
    assert len(old_r) == 1 and old_r[0] != 0
    scale = pow(old_r[0], -1, q)
    return [(value * scale) % q for value in old_s]


def main() -> None:
    d, q = 512, 2689
    m = d // 2
    r = m // 2

    # v = X^(m/2-1) + X^(m/2) + X^(m/2+1).
    v = [0] * m
    for exponent in (r - 1, r, r + 1):
        v[exponent] = 1

    # f is the binary inverse of v modulo p=X^m+1.
    p = [1] + [0] * (m - 1) + [1]
    f = poly_inv_mod2(v, p)

    one = [1] + [0] * (m - 1)
    assert poly_mul_mod(f, v, m) == one
    assert sum(f) & 1 == 1

    den = [0] * (d + 1)
    den[0] = den[d] = 1
    assert poly_gcd(f, den, q) == [1]
    f_inv_q = poly_inv_mod_q(f, den, q)
    bezout_product = poly_mul_mod_q(f, f_inv_q, q)
    _, f_product_remainder = poly_divmod(bezout_product, den, q)
    assert f_product_remainder == [1]

    # For t=q*X^r and m=0, line 5 of Algorithm 6 is u=X^(m-1).
    tprime = poly_mul_mod([1 if i == r else 0 for i in range(m)], v, m)
    exact_candidates = []
    for i in range(m):
        residual_high = [
            tprime[j] ^ v[(j - i) % m] for j in range(m // 2, m)
        ]
        if not any(residual_high):
            exact_candidates.append(i)
    assert exact_candidates == [r]

    u = [0] * m
    u[m - 1] = 1
    hamming = sum(u)
    matched = []
    correlations = []
    for i in range(m):
        # Initial orientation which contains the true shift r:
        # coefficient i is sum_j u_j v_(j-i).
        value = sum(u[j] * v[(j - i) % m] for j in range(m))
        correlations.append(value)
        if value == hamming:
            matched.append(i)
    assert matched == [r - 2, r - 1, r]

    a6 = [0] * m
    for i in matched:
        a6[i] ^= 1
    delta = [0] * m
    delta[r] ^= 1
    for i, value in enumerate(a6):
        delta[i] ^= value
    recovered_residue = poly_mul_mod(delta, v, m)
    recovered_low = recovered_residue[: m // 2]
    assert any(recovered_low)

    print(f"d={d}, q={q}, m={m}, r={r}")
    print(f"weight(f)={sum(f)}, f(1) mod 2={sum(f) & 1}")
    print(f"gcd(f, X^d+1) modulo q={poly_gcd(f, den, q)}")
    print(f"f*f^-1 mod (q,X^d+1)={f_product_remainder}")
    print(f"Algorithm 5 unique exact shift={exact_candidates}")
    print(f"Algorithm 6 matched shifts={matched}")
    print(f"Algorithm 6 output exponents={[i for i, x in enumerate(a6) if x]}")
    print(f"recovered Low residue exponents={[i for i, x in enumerate(recovered_low) if x]}")
    print("correct Low message had no nonzero positions")

    # The same symbolic collision occurs at the two larger profiles.
    for other_d, other_q in ((1024, 4481), (2048, 7681)):
        other_m = other_d // 2
        other_r = other_m // 2
        other_v = [0] * other_m
        for exponent in (other_r - 1, other_r, other_r + 1):
            other_v[exponent] = 1
        other_p = [1] + [0] * (other_m - 1) + [1]
        other_f = poly_inv_mod2(other_v, other_p)
        other_den = [0] * (other_d + 1)
        other_den[0] = other_den[other_d] = 1
        other_one = [1] + [0] * (other_m - 1)
        assert poly_mul_mod(other_f, other_v, other_m) == other_one
        assert poly_gcd(other_f, other_den, other_q) == [1]
        other_u = [0] * other_m
        other_u[other_m - 1] = 1
        other_matches = []
        for i in range(other_m):
            value = sum(
                other_u[j] * other_v[(j - i) % other_m]
                for j in range(other_m)
            )
            if value == 1:
                other_matches.append(i)
        assert other_matches == [other_r - 2, other_r - 1, other_r]
        print(
            f"d={other_d}, q={other_q}: weight(f)={sum(other_f)}, "
            f"Algorithm 6 matches={other_matches}"
        )


if __name__ == "__main__":
    main()
