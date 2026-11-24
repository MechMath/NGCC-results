#!/usr/bin/env python3
"""Independent packed-word implementation of CHIME lambda.

Each 256-bit array is a Python integer whose bit i is coordinate i, with
coordinate 0 leftmost.  This representation does not use the list-of-bits
implementation in chime_lambda_check.py, and is cross-checked against it.
"""

import random

import chime_lambda_check as lists

WIDTH = 256
MASK = (1 << WIDTH) - 1
WORD = (1 << 64) - 1
NAMES = ("A0", "A1", "B0", "B1", "C0", "C1")


def chunks(a, width):
    mask = (1 << width) - 1
    return [(a >> (width * k)) & mask for k in range(WIDTH // width)]


def perm(a, width, order):
    cs = chunks(a, width)
    return sum(cs[k] << (width * out) for out, k in enumerate(order))


def p32(a):
    return perm(a, 32, (3, 0, 1, 2, 7, 4, 5, 6))


def p32i(a):
    return perm(a, 32, (1, 2, 3, 0, 5, 6, 7, 4))


def p64(a):
    return perm(a, 64, (1, 2, 3, 0))


def p64i(a):
    return perm(a, 64, (3, 0, 1, 2))


def sw64(a):
    return perm(a, 64, (1, 0, 3, 2))


def sw128(a):
    return perm(a, 128, (1, 0))


def rol(a, n):
    out = 0
    for k, lane in enumerate(chunks(a, 64)):
        rotated = ((lane >> n) | (lane << (64 - n))) & WORD
        out |= rotated << (64 * k)
    return out


def shl7(a):
    out = 0
    for k, lane in enumerate(chunks(a, 64)):
        out |= (lane >> 7) << (64 * k)
    return out


def shr5(a):
    out = 0
    for k, lane in enumerate(chunks(a, 64)):
        out |= ((lane << 5) & WORD) << (64 * k)
    return out


def lam(x):
    a0, a1, b0, b1, c0, c1 = x
    b1 ^= p32(c1)
    b0 ^= a1
    c0 ^= rol(a0, 29)
    b1 ^= rol(a1, 31)
    c1 ^= rol(a0, 13)
    c0 ^= b1
    a0 = p64(a0)
    c1 ^= p32(b1)
    a1 = sw128(a1)
    a0 ^= sw64(c0)
    a1 ^= p32(b0)
    b1 ^= shl7(a0)
    c1 ^= shr5(a1)
    return [a0, a1, b0, b1, c0, c1]


def lam_inv(y):
    ya0, ya1, yb0, yb1, yc0, yc1 = y
    a1p = ya1 ^ p32(yb0)
    xa1 = sw128(a1p)
    a0p = ya0 ^ sw64(yc0)
    xa0 = p64i(a0p)
    b1p = yb1 ^ shl7(ya0)
    xc0 = yc0 ^ b1p ^ rol(xa0, 29)
    xc1 = yc1 ^ shr5(ya1) ^ p32(b1p) ^ rol(xa0, 13)
    xb0 = yb0 ^ xa1
    xb1 = b1p ^ rol(xa1, 31) ^ p32(xc1)
    return [xa0, xa1, xb0, xb1, xc0, xc1]


def list_to_packed(s):
    return [
        sum(bit << i for i, bit in enumerate(row))
        for row in s
    ]


def packed_to_list(s):
    return [
        [(a >> i) & 1 for i in range(WIDTH)]
        for a in s
    ]


def rank(columns):
    rows = [0] * (6 * WIDTH)
    for image in columns:
        while image:
            p = image.bit_length() - 1
            if rows[p]:
                image ^= rows[p]
            else:
                rows[p] = image
                break
    return sum(bool(x) for x in rows)


def main():
    # All standard basis vectors, not sampled cases.
    inverse_ok = True
    columns = []
    for j in range(6 * WIDTH):
        basis = [0] * 6
        basis[j // WIDTH] = 1 << (j % WIDTH)
        image = lam(basis)
        inverse_ok &= lam_inv(image) == basis
        columns.append(sum(image[a] << (a * WIDTH) for a in range(len(NAMES))))

    r = rank(columns)

    # Cross-check random states between two implementations.
    rng = random.Random(0xC41E)
    cross_ok = True
    for _ in range(100):
        lo = [rng.getrandbits(WIDTH) for _ in NAMES]
        from_words = lam(lo)
        from_lists = lists.lam(packed_to_list(lo))
        cross_ok &= packed_to_list(from_words) == from_lists

    d = sum(1 << (31 + 4 * j) for j in range(8))
    d |= sum(1 << (159 + 4 * j) for j in range(8))
    b1 = (1 << 0) | (1 << 128)
    K = [0, d, 0, b1, 0, 0]
    L = lam(K)
    supports = {
        name: [i for i in range(WIDTH) if (L[k] >> i) & 1]
        for k, name in enumerate(NAMES)
        if L[k]
    }

    expected = {
        "A0": [68 + 4*j for j in range(7)] + [196 + 4*j for j in range(7)],
        "A1": (
            [31 + 4*j for j in range(8)]
            + [63 + 4*j for j in range(8)]
            + [159 + 4*j for j in range(8)]
            + [191 + 4*j for j in range(8)]
        ),
        "B0": [31 + 4*j for j in range(8)] + [159 + 4*j for j in range(8)],
        "B1": (
            [4*j for j in range(1, 8)]
            + [65 + 4*j for j in range(6)]
            + [132 + 4*j for j in range(7)]
            + [193 + 4*j for j in range(6)]
        ),
        "C0": [4*j for j in range(1, 8)] + [132 + 4*j for j in range(7)],
        "C1": [72 + 4*j for j in range(7)] + [200 + 4*j for j in range(7)],
    }
    assert inverse_ok and cross_ok and r == 1536
    assert supports == expected and sum(x.bit_count() for x in L) == 116
    assert (L[3] >> 4) & 1

    print("packed_inverse_on_standard_basis", inverse_ok)
    print("packed_rank", r, "kernel_dimension", 6 * WIDTH - r)
    print("cross_implementation_100", cross_ok)
    print("packed_lambda_K_support", supports)
    print("packed_lambda_K_weight", sum(x.bit_count() for x in L))
    print("B1_4", (L[3] >> 4) & 1)


if __name__ == "__main__":
    main()
