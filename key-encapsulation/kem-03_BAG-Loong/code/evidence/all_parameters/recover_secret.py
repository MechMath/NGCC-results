#!/usr/bin/env python3
"""Recover BAG-Loong-128 X from the submitted keygen output.

The shipped sampler constructs every support as the fixed coordinate span
<e_0,...,e_{t-1}>.  Consequently S=HX+Y is a linear system over F_2.
"""

import pathlib
import struct
import sys
import time

N = 42
M = 47
N1 = 10
TX = 5
TY = 5
Y_SUPPORT = (0, 1, 2, 3, 5)
Y_OUTSIDE = tuple(b for b in range(M) if b not in Y_SUPPORT)
MODULUS = (1 << 47) | (1 << 5) | 1


def field_mul(a: int, b: int) -> int:
    z = 0
    while b:
        if b & 1:
            z ^= a
        b >>= 1
        a <<= 1
        if a >> M:
            a ^= MODULUS
    return z


def parse_bits(data: bytes, count: int):
    return [
        sum(((data[(i * M + b) >> 3] >> (7 - ((i * M + b) & 7))) & 1) << b
            for b in range(M))
        for i in range(count)
    ]


def solve_column(h, s_col, j):
    """Solve the out-of-support syndrome equations for X[:,j]."""
    nvars = N * TX
    equations = []
    for r in range(N):
        for out_bit in Y_OUTSIDE:
            coeff = 0
            rhs = (s_col[r] >> out_bit) & 1
            for i in range(N):
                products = [field_mul(h[r][i], 1 << a) for a in range(TX)]
                for a, product in enumerate(products):
                    if (product >> out_bit) & 1:
                        coeff ^= 1 << (i * TX + a)
            equations.append(coeff | (rhs << nvars))

    pivots = {}
    for row in equations:
        coeff = row & ((1 << nvars) - 1)
        rhs = (row >> nvars) & 1
        while coeff:
            p = coeff.bit_length() - 1
            if p not in pivots:
                pivots[p] = (coeff, rhs)
                break
            old_coeff, old_rhs = pivots[p]
            coeff ^= old_coeff
            rhs ^= old_rhs
        else:
            if rhs:
                raise RuntimeError(f"inconsistent system in column {j}")

    solution = 0
    for p in sorted(pivots):
        coeff, rhs = pivots[p]
        bit = rhs ^ ((coeff & solution).bit_count() & 1)
        if bit:
            solution |= 1 << p
    return solution, len(pivots), len(equations)


def set_parameters(n, m, n1, dx, dy, intersection):
    global N, M, N1, TX, TY, Y_SUPPORT, Y_OUTSIDE, MODULUS
    N, M, N1, TX, TY = n, m, n1, dx, dy
    union = dx + dy - intersection
    Y_SUPPORT = tuple(range(intersection)) + tuple(range(dx, union))
    Y_OUTSIDE = tuple(b for b in range(M) if b not in Y_SUPPORT)
    if n == 42:
        MODULUS = (1 << 47) | (1 << 5) | 1
    elif n == 65:
        MODULUS = (1 << 67) | (1 << 5) | (1 << 2) | (1 << 1) | 1
    elif n == 83:
        MODULUS = (1 << 83) | (1 << 7) | (1 << 4) | (1 << 2) | 1
    elif n == 104:
        MODULUS = (1 << 97) | (1 << 6) | 1
    else:
        raise ValueError("unsupported parameter set")


def main(prefix):
    p = pathlib.Path(prefix)
    pk = p.with_suffix(".pk").read_bytes()
    sk = p.with_suffix(".sk").read_bytes()
    raw_h = p.with_suffix(".h").read_bytes()

    words = (M + 63) // 64
    element_bytes = words * 8
    assert len(raw_h) == N * N * element_bytes
    seed_bytes = {42: 32, 65: 64, 83: 96, 104: 128}[N]
    assert len(pk) == seed_bytes + (N * N1 * M + 7) // 8
    assert len(sk) == len(pk)
    h_words = struct.unpack("<" + "Q" * (N * N * words), raw_h)
    h_flat = [
        sum(h_words[i * words + w] << (64 * w) for w in range(words))
        for i in range(N * N)
    ]
    h = [h_flat[r * N:(r + 1) * N] for r in range(N)]
    s = parse_bits(pk[seed_bytes:], N * N1)
    truth = parse_bits(sk[seed_bytes:], N * N1)

    started = time.perf_counter()
    recovered = [0] * (N * N1)
    ranks = []
    equation_counts = []
    for j in range(N1):
        sol, rank, eq_count = solve_column(
            h, [s[r * N1 + j] for r in range(N)], j
        )
        ranks.append(rank)
        equation_counts.append(eq_count)
        for i in range(N):
            value = 0
            for a in range(TX):
                if (sol >> (i * TX + a)) & 1:
                    value ^= 1 << a
            recovered[i * N1 + j] = value
    elapsed = time.perf_counter() - started

    # Independently check S-HX has no nonzero coefficient outside Supp(Y).
    y_support_max = 0
    y_outside_mask = sum(1 << bit for bit in Y_OUTSIDE)
    outside_violation = 0
    for r in range(N):
        for j in range(N1):
            hx = 0
            for i in range(N):
                hx ^= field_mul(h[r][i], recovered[i * N1 + j])
            y = s[r * N1 + j] ^ hx
            y_support_max = max(y_support_max, y.bit_length())
            outside_violation |= y & y_outside_mask

    exact = recovered == truth
    print(f"columns={N1}")
    print(f"equations_per_column={equation_counts[0]}")
    print(f"unknowns_per_column={N * TX}")
    print(f"rank_per_column={ranks}")
    print(f"max_y_bit_length={y_support_max}")
    print(f"y_outside_support_violation={outside_violation}")
    print(f"secret_x_exact={exact}")
    print(f"elapsed_python_seconds={elapsed:.6f}")
    if not exact or outside_violation:
        return 1
    return 0


if __name__ == "__main__":
    if len(sys.argv) == 8:
        set_parameters(*(int(x) for x in sys.argv[2:]))
    elif len(sys.argv) != 2:
        raise SystemExit(
            "usage: recover_secret.py PREFIX [N M N1 DX DY INTERSECTION]"
        )
    sys.exit(main(sys.argv[1]))
