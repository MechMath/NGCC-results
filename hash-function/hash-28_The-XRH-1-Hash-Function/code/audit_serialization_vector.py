#!/usr/bin/env python3
"""Second, index-only implementation used to cross-check audit_serialization.py."""

import hashlib


SBOX = (
    4, 14, 10, 5, 9, 24, 20, 0, 18, 28, 30, 21, 2, 23, 29, 13,
    22, 27, 15, 7, 26, 12, 16, 3, 8, 1, 19, 31, 25, 11, 17, 6,
)

# Coefficients multiplying [a0,a1,a2,a3], recovered from the printed equation
# [b3,b2,b1,b0]^T = M [a3,a2,a1,a0]^T.
MDS_COEFFS = (
    (1, 3, 2, 2),
    (4, 6, 3, 1),
    (4, 4, 1, 3),
    (3, 1, 2, 3),
)


def gf_mul(a, b):
    out = 0
    while b:
        if b & 1:
            out ^= a
        b >>= 1
        a <<= 1
        if a & 32:
            a ^= 37  # x^5+x^2+1
    return out & 31


def mix(values):
    out = []
    for coeffs in MDS_COEFFS:
        value = 0
        for coeff, item in zip(coeffs, values):
            value ^= gf_mul(coeff, item)
        out.append(value)
    return out


def coordinate(index, order):
    if order == "R":
        return index // 64, index % 64
    return index % 20, index // 20


def coordinate_index(row, column, order):
    return 64 * row + column if order == "R" else 20 * column + row


def logical_to_matrix(index, order):
    row, column = coordinate(index, order)
    return 64 * row + column


def shifted_index(row, column, round_number):
    group = row // 5
    kind = round_number % 3
    if kind == 0:
        width, amount = 4, group
    elif kind == 1:
        width, amount = 16, 4 * group
    else:
        width, amount = 64, 16 * group
    base = (column // width) * width
    return row, base + (column % width + amount) % width


def one_round(bits, round_number):
    out = bits[:]
    for column in range(64):
        values = []
        for block in range(4):
            value = 0
            for lane in range(5):
                row = 5 * block + lane
                value |= bits[64 * row + column] << lane
            values.append(SBOX[value])
        values = [SBOX[value] for value in mix(values)]
        for block, value in enumerate(values):
            for lane in range(5):
                row = 5 * block + lane
                out[64 * row + column] = (value >> lane) & 1

    shifted = [0] * 1280
    for row in range(20):
        for column in range(64):
            nr, nc = shifted_index(row, column, round_number)
            shifted[64 * nr + nc] = out[64 * row + column]
    for column in range(64):
        values = [0] * 4
        for block in range(4):
            for lane in range(5):
                values[block] |= shifted[64 * (5 * block + lane) + column] << lane
        values = mix(values)
        for block, value in enumerate(values):
            for lane in range(5):
                out[64 * (5 * block + lane) + column] = (value >> lane) & 1
    inverse = [0] * 1280
    for row in range(20):
        for column in range(64):
            nr, nc = shifted_index(row, column, round_number)
            inverse[64 * row + column] = out[64 * nr + nc]
    return inverse


def permutation(bits, first=0, last=18):
    out = bits[:]
    for round_number in range(first, last):
        out = one_round(out, round_number)
        for column in range(64):
            out[column] ^= 0  # RC_r = 0 in this witness.
    return out


def xrh(message, n, order):
    rate = 1280 - n - 64
    capacity = n + 64
    zeros = (-len(message) - 2) % rate
    padded = message + [1] + [0] * zeros + [1]
    vector_bits = [0] * 1280
    for offset in range(0, len(padded), rate):
        block = padded[offset:offset + rate]
        x = vector_bits[:]
        for index, bit in enumerate(block):
            x[logical_to_matrix(index, order)] ^= bit
        after_g = permutation(x, 0, 9)
        for index in range(capacity):
            matrix_index = logical_to_matrix(index, order)
            after_g[matrix_index] ^= x[matrix_index]
        vector_bits = permutation(after_g, 9, 18)

    output = [
        vector_bits[logical_to_matrix(index, order)]
        for index in range(rate)
    ]
    while len(output) < n:
        vector_bits = permutation(vector_bits)
        output.extend(
            vector_bits[logical_to_matrix(index, order)]
            for index in range(rate)
        )
    return output[:n]


def fingerprint(bits):
    packed = bytearray()
    for offset in range(0, len(bits), 8):
        value = 0
        for bit in bits[offset:offset + 8]:
            value = 2 * value + bit
        packed.append(value)
    return hashlib.sha256(bytes(packed)).hexdigest()


for n in (512, 768, 1024):
    row = xrh([1], n, "R")
    col = xrh([1], n, "C")
    print(
        n,
        row != col,
        sum(a != b for a, b in zip(row, col)),
        fingerprint(row),
        fingerprint(col),
    )
