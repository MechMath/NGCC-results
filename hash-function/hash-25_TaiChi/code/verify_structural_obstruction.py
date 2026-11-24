#!/usr/bin/env python3
"""Reproducible arithmetic for the TaiChi P1920 bijectivity obstruction.

This script is a research note. The submitted proof is the determinant argument;
the script is only a convenient way to recompute its finite polynomial expansion.
"""

from itertools import permutations


MASK64 = (1 << 64) - 1
N1 = [0, 1, 2, 4, 3, 5, 6, 7, 13, 14, 15, 16, 15, 18, 11, 20]
N2 = [1, 2, 4, 3, 5, 6, 0, 11, 8, 9, 10, 12, 17, 14, 19, 13]
SHIFTS = [8, 0, 0, 0, 0, 0, 23, 62, 35, 14, 48, 1, 57, 63, 58, 22]
OUTPUT_ROTATIONS = [0, 15, 48, 63, 6, 33]
Q = [
    2, 18, 1, 16, 3, 27, 5, 28, 7, 21, 14, 29, 26, 0, 22, 13,
    12, 24, 31, 10, 15, 19, 25, 4, 8, 30, 17, 6, 23, 9, 11, 20,
]


def rotl64(x: int, r: int) -> int:
    r %= 64
    if r == 0:
        return x & MASK64
    return ((x << r) | (x >> (64 - r))) & MASK64


def ring_mul(a: int, b: int) -> int:
    """Multiply modulo x^64 + 1 over F2."""
    out = 0
    while b:
        low = b & -b
        out ^= rotl64(a, low.bit_length() - 1)
        b ^= low
    return out


def mrm_matrix() -> list[list[int]]:
    # Word j of dependency i is the coefficient on input word x_j.
    dependency = [
        [int(j == i) for j in range(6)]
        for i in range(6)
    ]
    for k in range(16):
        dependency.append([
            dependency[N1[k]][j]
            ^ rotl64(dependency[N2[k]][j], SHIFTS[k])
            for j in range(6)
        ])
    return [
        [
            rotl64(dependency[16 + i][j], OUTPUT_ROTATIONS[i])
            for j in range(6)
        ]
        for i in range(6)
    ]


def determinant_mod_x64_plus_1(matrix: list[list[int]]) -> int:
    det = 0
    for perm in permutations(range(6)):
        term = 1
        for i in range(6):
            term = ring_mul(term, matrix[i][perm[i]])
        det ^= term
    return det


def bit_rank_of_mrm() -> int:
    rows = [0] * 384
    for input_word in range(6):
        for input_bit in range(64):
            y = [0] * 22
            y[input_word] = 1 << input_bit
            for k in range(16):
                y[6 + k] = y[N1[k]] ^ rotl64(y[N2[k]], SHIFTS[k])
            output = [
                rotl64(y[16 + i], OUTPUT_ROTATIONS[i])
                for i in range(6)
            ]
            column = 64 * input_word + input_bit
            for output_word, value in enumerate(output):
                while value:
                    low = value & -value
                    output_bit = low.bit_length() - 1
                    rows[64 * output_word + output_bit] |= 1 << column
                    value ^= low

    basis: dict[int, int] = {}
    for row in rows:
        value = row
        while value:
            pivot = value.bit_length() - 1
            if pivot in basis:
                value ^= basis[pivot]
            else:
                basis[pivot] = value
                break
    return len(basis)


def main() -> None:
    det = determinant_mod_x64_plus_1(mrm_matrix())
    rank = bit_rank_of_mrm()
    assert det == (1 << 28) ^ (1 << 51) ^ (1 << 59)
    assert det.bit_count() & 1
    assert rank == 384
    assert len(set(Q)) == 32
    assert Q[11] == 29 and Q[15] == 13
    print(f"MRM determinant over F2[x]/(x^64+1): 0x{det:016x}")
    print(f"MRM bit-matrix rank: {rank}")
    print("5-bit Q table has 32 distinct outputs")


if __name__ == "__main__":
    main()
