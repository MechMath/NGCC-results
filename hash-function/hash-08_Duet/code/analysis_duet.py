#!/usr/bin/env python3
"""Independent structural checks for the pinned Duet specification."""

from collections import Counter
from math import gcd


SBOX = [
    0x1A, 0x09, 0x10, 0x17, 0x07, 0x08, 0x15, 0x0E,
    0x19, 0x1F, 0x1E, 0x0C, 0x1B, 0x01, 0x04, 0x0A,
    0x05, 0x13, 0x0D, 0x0F, 0x16, 0x1C, 0x06, 0x18,
    0x11, 0x12, 0x14, 0x03, 0x1D, 0x02, 0x00, 0x0B,
]
M15_ROW = [1, 0, 0, 1, 1, 1, 0, 1, 1, 0, 0, 0, 0, 1, 0]
M30_ROW = [
    1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1,
    1, 1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0,
]


def circulant(row):
    n = len(row)
    return [[row[(j - i) % n] for j in range(n)] for i in range(n)]


def gf2_rank(rows):
    basis = {}
    for value in rows:
        while value:
            pivot = value.bit_length() - 1
            if pivot in basis:
                value ^= basis[pivot]
            else:
                basis[pivot] = value
                break
    return len(basis)


def branch_number(row):
    n = len(row)
    values = []
    for shift in range(n):
        rotated = [row[(i - shift) % n] for i in range(n)]
        values.append(sum(a ^ b for a, b in zip(row, rotated)))
    return min(values), values


def latin_square_circulant_branch(row):
    matrix = circulant(row)
    n = len(row)
    best = n + 1
    witness = None
    for mask in range(1, 1 << n):
        out = 0
        for i, bit in enumerate(row):
            if mask >> i & 1:
                for j, entry in enumerate(matrix[i]):
                    if entry:
                        out ^= 1 << j
        weight = out.bit_count()
        if weight < best:
            best, witness = weight, mask
    return best, witness


def ddt():
    counts = [[0] * 32 for _ in range(32)]
    for delta in range(32):
        for x in range(32):
            counts[delta][SBOX[x] ^ SBOX[x ^ delta]] += 1
    return counts


def lat():
    table = [[0] * 32 for _ in range(32)]
    for a in range(32):
        for b in range(32):
            total = 0
            for x in range(32):
                sign = -1 if ((a & x).bit_count() ^ (b & SBOX[x]).bit_count()) & 1 else 1
                total += sign
            table[a][b] = total
    return table


def ml_word(x, lane):
    mask = (1 << 64) - 1
    rol = lambda y, r: ((y << (r % 64)) | (y >> ((64 - r) % 64))) & mask
    return rol(x, lane) ^ rol(x, lane + 21) ^ rol(x, lane + 43)


def ms_slice(bits, row):
    n = len(row)
    matrix = circulant(row)
    out = 0
    for i, bit in enumerate(bits):
        if not bit:
            continue
        for j, entry in enumerate(matrix[i]):
            if entry:
                out ^= 1 << j
    return out


def active_columns(diff_words, m):
    """Count active S-box columns at every bit position."""
    return sum(
        any((diff_words[5 * j + i] >> k) & 1 for i in range(5))
        for j in range(m)
        for k in range(64)
    )


def best_one_to_two_round(row):
    m = len(row) // 5
    counts = ddt()
    best = (10**9, None)
    for column in range(m):
        for inp in range(1, 32):
            for out in range(1, 32):
                weight = counts[inp][out]
                if not weight:
                    continue
                words = [0] * (5 * m)
                words[5 * column:5 * column + 5] = [(out >> i) & 1 for i in range(5)]
                after_ms = ms_slice(words, row)
                diff_words = [0] * (5 * m)
                for i in range(5 * m):
                    if (after_ms >> i) & 1:
                        diff_words[i] = ml_word(1, i)
                active = active_columns(diff_words, m)
                candidate = (active, weight, column, inp, out, after_ms.bit_count())
                if candidate < best:
                    best = candidate
    return best


def main():
    for bits, row in ((15, M15_ROW), (30, M30_ROW)):
        matrix = circulant(row)
        rank = gf2_rank([sum(bit << j for j, bit in enumerate(line)) for line in matrix])
        block_branch, block_witnesses = branch_number(row)
        print(f"M{bits}: rank={rank}, circulant_block_branch={block_branch}")
        print(f"M{bits}: shifted row weights={Counter(block_witnesses)}")

    p = 1 ^ (1 << 21) ^ (1 << 43)
    mod = (1 << 64) ^ 1

    def poly_mod(a, b):
        while a and a.bit_length() >= b.bit_length():
            a ^= b << (a.bit_length() - b.bit_length())
        return a

    def poly_gcd(a, b):
        while b:
            a, b = b, poly_mod(a, b)
        return a

    ml_rank = gf2_rank([
        ((p >> i) | (p << (64 - i))) & ((1 << 64) - 1) for i in range(64)
    ])
    print(f"ML polynomial gcd with x^64+1: {poly_gcd(mod, p):#x}; matrix rank={ml_rank}")

    counts = ddt()
    no_one_bit_fixed = all(counts[1 << i][1 << i] == 0 for i in range(5))
    print(f"S-box one-bit fixed differentials absent: {no_one_bit_fixed}")
    print("S-box DDT row support:",
          {delta: sum(bool(x) for x in counts[delta]) for delta in range(1, 32)})

    linear = lat()
    zero_pairs = []
    for a in range(1, 32):
        for b in range(1, 32):
            if linear[a][b] == 0:
                zero_pairs.append((a, b))
    print(f"S-box nonzero zero-correlation mask pairs: {len(zero_pairs)}")

    print("best one-S-box differential after two rounds:")
    print("f960", best_one_to_two_round(M15_ROW))
    print("f1920", best_one_to_two_round(M30_ROW))


if __name__ == "__main__":
    main()
