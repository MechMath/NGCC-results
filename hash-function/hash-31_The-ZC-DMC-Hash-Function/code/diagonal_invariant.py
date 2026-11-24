#!/usr/bin/env python3
"""Exploratory GF(2) computation for the diagonal ZC-1536 subspace."""

MASK = (1 << 64) - 1
RHO = [(0, 0), (3, 3), (5, 0)]
THETA = (20, 56)


def rol(v: int, n: int) -> int:
    n %= 64
    return v if n == 0 else ((v << n) | (v >> (64 - n))) & MASK


def rho(s: list[list[int]], inverse: bool = False) -> list[list[int]]:
    out = [[0] * 8 for _ in range(3)]
    for y, (a, b) in enumerate(RHO):
        if inverse:
            a, b = -a, -b
        for x in range(8):
            out[y][x] = rol(s[y][(x - a) % 8], b)
    return out


def theta(s: list[list[int]]) -> list[list[int]]:
    parity = [s[0][x] ^ s[1][x] ^ s[2][x] for x in range(8)]
    effect = [rol(parity[(x - 1) % 8], THETA[0])
              ^ rol(parity[(x - 1) % 8], THETA[1]) for x in range(8)]
    return [[s[y][x] ^ effect[x] for x in range(8)] for y in range(3)]


def linear_round(s: list[list[int]]) -> list[list[int]]:
    return rho(theta(rho(s)))


def basis_diag(x: int, z: int) -> list[list[int]]:
    v = 1 << z
    return [[v if xx == x else 0 for xx in range(8)] for _ in range(3)]


def echelon(rows: list[int]) -> dict[int, int]:
    pivots: dict[int, int] = {}
    for v in rows:
        while v:
            p = v.bit_length() - 1
            if p in pivots:
                v ^= pivots[p]
            else:
                pivots[p] = v
                break
    return pivots


def nullspace_basis(pivots: dict[int, int], n: int) -> list[int]:
    free = [j for j in range(n) if j not in pivots]
    basis = []
    for f in free:
        x = 1 << f
        for p in sorted(pivots):
            row = pivots[p]
            if ((row & x).bit_count() & 1):
                x ^= 1 << p
        basis.append(x)
    return basis


def main() -> None:
    images = []
    for x in range(8):
        for z in range(64):
            images.append(linear_round(basis_diag(x, z)))

    # Every output coordinate of the 512-dimensional diagonal space must lie
    # in the diagonal space after one linear round.  One row per equation
    # output_plane0 xor output_plane1 and output_plane0 xor output_plane2.
    packs = []
    for x in range(8):
        for z in range(64):
            # The two equations need separate rows; build them independently.
            bits01 = 0
            bits02 = 0
            for j, img in enumerate(images):
                if ((img[0][x] ^ img[1][x]) >> z) & 1:
                    bits01 |= 1 << j
                if ((img[0][x] ^ img[2][x]) >> z) & 1:
                    bits02 |= 1 << j
            packs.extend([bits01, bits02])
    pivots = echelon(packs)
    basis = nullspace_basis(pivots, 512)
    print({"equations": len(packs), "rank": len(pivots),
           "kernel_dimension": len(basis)})
    for x in range(8):
        print(x, [hex((v >> (64 * x)) & MASK) for v in basis])


if __name__ == "__main__":
    main()
