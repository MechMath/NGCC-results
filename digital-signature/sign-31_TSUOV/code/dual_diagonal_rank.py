#!/usr/bin/env python3
"""Exact F_31 rank check for the diagonal TSUOV dual map.

For a Table 1 profile, E_d is the first m1 columns of multiplication by z^d
in K=F_31[z]/(g).  This script forms the horizontal stack

    D = (E_{h(1,1)} | ... | E_{h(k,k)})

and Gaussian-eliminates it over F_31.  It prints the rank and pivots.
"""

Q = 31
PROFILES = {
    "TSUOV-128": (61, 11, 88, (1, 3, 4)),
    "TSUOV-256": (114, 16, 160, (1, 4, 6)),
    "TSUOV-512": (218, 10, 240, (1, 12, 15)),
}


def powers_of_z(m2, g, top):
    """Coefficient rows of z^e mod (z^m2-z^2-g[1]z-g[0])."""
    out = [[1] + [0] * (m2 - 1)]
    for _ in range(1, top + 1):
        prev = out[-1]
        nxt = [0] + prev[:-1]
        for j, c in enumerate(g):
            nxt[j] = (nxt[j] + c * prev[-1]) % Q
        out.append(nxt)
    return out


def diagonal_exponents(k):
    return [
        ((i) * (2 * k - i + 1)) // 2 + k - 1 - i
        for i in range(k)
    ]


def rank_and_pivots(rows, ncols):
    a = [row[:] for row in rows]
    rank = 0
    pivots = []
    for col in range(ncols):
        pivot = next(
            (r for r in range(rank, len(a)) if a[r][col] % Q), None
        )
        if pivot is None:
            continue
        a[rank], a[pivot] = a[pivot], a[rank]
        inv = pow(a[rank][col], -1, Q)
        a[rank] = [(x * inv) % Q for x in a[rank]]
        for r in range(len(a)):
            if r != rank and a[r][col] % Q:
                factor = a[r][col] % Q
                a[r] = [
                    (a[r][j] - factor * a[rank][j]) % Q
                    for j in range(ncols)
                ]
        pivots.append(col)
        rank += 1
        if rank == len(a) or rank == ncols:
            break
    return rank, pivots


def main():
    for name, (m1, k, m2, g) in PROFILES.items():
        exps = diagonal_exponents(k)
        zpow = powers_of_z(m2, g, max(exps) + m1 - 1)
        # One row of the horizontal stack, with all k diagonal blocks.
        rows = [
            [zpow[d + a][r] for d in exps for a in range(m1)]
            for r in range(m2)
        ]
        rank, pivots = rank_and_pivots(rows, k * m1)
        print(name)
        print("  diagonal exponents:", exps)
        print(f"  diagonal-stack rank: {rank}/{m2}")
        print("  pivots:", pivots)
        assert rank == m2


if __name__ == "__main__":
    main()
