#!/usr/bin/env python3
"""Small exact checks for the structural observations on the allowed WChain spec.

These checks are observations, not execution evidence for a crypto_run claim.
"""

from collections import Counter, defaultdict


W = 64
PI16_1 = 0x243F
D = (0, 1, 10, 20, 25, 32, 41, 46, 50)


def sbox_column(x: int) -> int:
    a = [(x >> i) & 1 for i in range(9)]
    b = [a[i] ^ (a[(i + 1) % 9] & a[(i + 2) % 9]) for i in range(9)]
    return sum(bit << i for i, bit in enumerate(b))


def rotl(x: int, n: int) -> int:
    n %= W
    return ((x << n) | (x >> (W - n))) & ((1 << W) - 1) if n else x


def sbox_lanes(x: list[int]) -> list[int]:
    return [
        x[i] ^ (x[(i + 1) % 9] & x[(i + 2) % 9])
        for i in range(9)
    ]


def gf2_rank(rows: list[list[int]]) -> int:
    matrix = [row[:] for row in rows]
    rank = 0
    for col in range(len(matrix[0]) if matrix else 0):
        pivot = next(
            (i for i in range(rank, len(matrix)) if matrix[i][col] & 1),
            None,
        )
        if pivot is None:
            continue
        matrix[rank], matrix[pivot] = matrix[pivot], matrix[rank]
        for i in range(rank + 1, len(matrix)):
            if matrix[i][col] & 1:
                matrix[i] = [
                    left ^ right
                    for left, right in zip(matrix[i], matrix[rank])
                ]
        rank += 1
    return rank


def check_sbox_and_zero_preimages() -> None:
    outputs = [sbox_column(x) for x in range(512)]
    inverse = defaultdict(list)
    for x, y in enumerate(outputs):
        inverse[y].append(x)

    assert inverse[0] == [0, 511]
    assert outputs[0] == outputs[511] == 0
    assert len(inverse) == 455

    # Every state with nine identical lanes is in the round-zero affine set.
    for w in (0, 1, PI16_1, (1 << W) - 1, 0x0123456789ABCDEF):
        assert sbox_lanes([w] * 9) == [0] * 9

    print(
        "S-box image size:",
        len(inverse),
        "preimage-size distribution:",
        dict(Counter(map(len, inverse.values()))),
    )
    print("zero preimages:", inverse[0])
    print("Version I Round_j(C_j XOR [w]) = 0 for every tested w")


def check_first_seed_intersection() -> None:
    """Check the obvious seed-collision route at the actual first compression.

    For a same-suffix scheduler collision under the all-one seed difference,
    D(B0) must have equal bits across all nine lanes.  For a round-1 zero-
    preimage collision, B0 must be C1 XOR [T].  At V=0 this asks whether
    C1 XOR [T] lies in the 64-dimensional set H of vectors whose D-image has
    nine identical lanes.  The resulting GF(2) system is inconsistent.
    """

    # Variables t[0..63], u[0..63].  For every lane i and bit z:
    # C_i[z] XOR t[z] = u[z-d_i].
    rows: list[list[int]] = []
    rhs: list[int] = []
    for i, di in enumerate(D):
        ci = rotl(PI16_1, i)
        for z in range(W):
            row = [0] * (2 * W)
            row[z] = 1
            row[W + ((z - di) % W)] = 1
            rows.append(row)
            rhs.append((ci >> z) & 1)

    coefficient_rank = gf2_rank(rows)
    augmented_rank = gf2_rank(
        [row + [value] for row, value in zip(rows, rhs)]
    )
    assert coefficient_rank < augmented_rank
    print(
        "first-seed intersection: inconsistent",
        f"(rank {coefficient_rank}, augmented rank {augmented_rank})",
    )


if __name__ == "__main__":
    check_sbox_and_zero_preimages()
    check_first_seed_intersection()
