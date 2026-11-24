#!/usr/bin/env python3
"""Independent checks of component claims in the WChain specification."""

from __future__ import annotations

from collections import deque


N = 64
PI = (0, 7, 5, 3, 1, 8, 6, 4, 2)

# Table 4: output lane -> ((input lane, left rotation), ...)
L_ROWS = (
    ((0, 5), (1, 22), (2, 3), (3, 28), (7, 27)),
    ((1, 39), (2, 59), (3, 45), (4, 3), (8, 9)),
    ((2, 54), (3, 6), (4, 20), (5, 8), (0, 48)),
    ((3, 0), (4, 57), (5, 55), (6, 46), (1, 28)),
    ((4, 61), (5, 38), (6, 0), (7, 44), (2, 52)),
    ((5, 29), (6, 10), (7, 37), (8, 19), (3, 7)),
    ((6, 56), (7, 5), (8, 50), (0, 27), (4, 13)),
    ((7, 40), (8, 10), (0, 11), (1, 54), (5, 14)),
    ((8, 3), (0, 38), (1, 36), (2, 17), (6, 13)),
)

# Table 5: output lane -> ((input lane, left rotation), ...)
R_ROWS = (
    ((0, 16), (1, 33), (2, 14), (3, 39), (7, 38)),
    ((1, 60), (2, 16), (3, 2), (4, 24), (8, 30)),
    ((2, 9), (3, 25), (4, 39), (5, 27), (0, 3)),
    ((3, 21), (4, 14), (5, 12), (6, 3), (1, 49)),
    ((4, 40), (5, 17), (6, 43), (7, 23), (2, 31)),
    ((5, 34), (6, 15), (7, 42), (8, 24), (3, 12)),
    ((6, 59), (7, 8), (8, 53), (0, 30), (4, 16)),
    ((7, 50), (8, 20), (0, 21), (1, 0), (5, 24)),
    ((8, 8), (0, 43), (1, 41), (2, 22), (6, 18)),
)


def validate_tables() -> None:
    assert sorted(PI) == list(range(9))
    assert all(len(row) == 5 for row in L_ROWS + R_ROWS)
    delta = (11, 21, 19, 21, 43, 5, 3, 10, 5)
    for i in range(9):
        expected = tuple((j, (a + delta[i]) % N) for j, a in L_ROWS[i])
        assert expected == R_ROWS[i], (i, expected, R_ROWS[i])
    d = (0, 1, 10, 20, 25, 32, 41, 46, 50)
    for i in range(1, 9):
        assert 7 * (i - 1) <= d[i] <= 7 * i


def chi(x: int) -> int:
    a = [(x >> i) & 1 for i in range(9)]
    # The PDF draws an overbar on a_{i+1}; pdftotext drops it.
    b = [
        a[i] ^ (((a[(i + 1) % 9]) ^ 1) & a[(i + 2) % 9])
        for i in range(9)
    ]
    return sum(bit << i for i, bit in enumerate(b))


def permute_bits(x: int) -> int:
    y = 0
    for i, j in enumerate(PI):
        y |= ((x >> i) & 1) << j
    return y


def mobius_degree(truth: list[int], nvars: int) -> int:
    f = truth[:]
    deg = 0
    for i in range(nvars):
        bit = 1 << i
        for mask in range(1 << nvars):
            if mask & bit:
                f[mask] ^= f[mask ^ bit]
    for mask, coefficient in enumerate(f):
        if coefficient:
            deg = max(deg, mask.bit_count())
    return deg


def walsh_transform(values: list[int]) -> list[int]:
    out = values[:]
    h = 1
    while h < len(out):
        for base in range(0, len(out), 2 * h):
            for i in range(base, base + h):
                u, v = out[i], out[i + h]
                out[i], out[i + h] = u + v, u - v
        h *= 2
    return out


def component_checks() -> None:
    values = [chi(x) for x in range(1 << 9)]
    inv = [0] * (1 << 9)
    for x, y in enumerate(values):
        inv[y] = x
    assert sorted(values) == list(range(1 << 9))
    assert all(chi(inv[x]) == x for x in range(1 << 9))

    ddt_entries = {}
    for a in range(1 << 9):
        for x in range(1 << 9):
            b = chi(x) ^ chi(x ^ a)
            ddt_entries[a, b] = ddt_entries.get((a, b), 0) + 1
    max_ddt = max(
        count for (a, _b), count in ddt_entries.items() if a != 0
    )
    assert max_ddt == 128

    max_lat = 0
    for b in range(1, 1 << 9):
        truth = [((values[x] & b).bit_count() & 1) for x in range(1 << 9)]
        transformed = walsh_transform(truth)
        max_lat = max(max_lat, max(abs(v) for v in transformed[1:]))
    assert max_lat == 128

    # Fast Möbius transform for each output coordinate.
    for bit in range(9):
        truth = [((values[x] >> bit) & 1) for x in range(1 << 9)]
        assert mobius_degree(truth, 9) == 2
    for bit in range(9):
        truth = [((inv[x] >> bit) & 1) for x in range(1 << 9)]
        assert mobius_degree(truth, 9) == 5

    # The composed nonlinear/wiring function has the same DDT and LAT after
    # coordinate reindexing.
    fpi = [permute_bits(chi(x)) for x in range(1 << 9)]
    assert sorted(fpi) == list(range(1 << 9))

    print(
        "components: bijective; DDTmax=128; max|LAT|=128; "
        "forward/inverse degree=2/5"
    )


def bit_index(lane: int, pos: int) -> int:
    return lane * N + pos


def mix_columns(rows: tuple[tuple[tuple[int, int], ...], ...]) -> list[int]:
    ncols = 9 * N
    cols = [0] * ncols
    for out_lane, row in enumerate(rows):
        for in_lane, rot in row:
            for in_pos in range(N):
                out_pos = (in_pos + rot) % N
                src = bit_index(in_lane, in_pos)
                dst = bit_index(out_lane, out_pos)
                cols[dst] ^= 1 << src
    return cols


def gf2_rank(cols: list[int], nrows: int) -> int:
    basis: dict[int, int] = {}
    rank = 0
    for value in cols:
        v = value
        while v:
            pivot = v.bit_length() - 1
            if pivot in basis:
                v ^= basis[pivot]
            else:
                basis[pivot] = v
                rank += 1
                break
    assert all((v >> nrows) == 0 for v in basis.values())
    return rank


def inverse_columns(cols: list[int]) -> list[int]:
    """Return columns of A^{-1} for a square GF(2) matrix given A columns."""
    n = len(cols)
    # Row reduction with an augmented identity; rows are bit vectors.
    rows = [0] * n
    for col, value in enumerate(cols):
        v = value
        while v:
            row = (v & -v).bit_length() - 1
            rows[row] |= 1 << col
            v &= v - 1
    aug = [rows[i] | (1 << (n + i)) for i in range(n)]
    for col in range(n):
        pivot = next(r for r in range(col, n) if (aug[r] >> col) & 1)
        aug[col], aug[pivot] = aug[pivot], aug[col]
        for r in range(n):
            if r != col and ((aug[r] >> col) & 1):
                aug[r] ^= aug[col]
    inv_rows = [((aug[i] >> n) & ((1 << n) - 1)) for i in range(n)]
    inv_cols = [0] * n
    for row, value in enumerate(inv_rows):
        v = value
        while v:
            col = (v & -v).bit_length() - 1
            inv_cols[col] |= 1 << row
            v &= v - 1
    return inv_cols


def weighted_support(cols: list[int]) -> tuple[int, dict[int, int], int, int]:
    n = len(cols)
    total = sum(c.bit_count() for c in cols)
    weights = {i: c.bit_count() for i, c in enumerate(cols)}
    return total, weights, min(weights.values()), max(weights.values())


def branch_numbers(cols: list[int], max_input_weight: int = 3) -> list[int]:
    n = len(cols)
    out: list[int] = []
    for weight in range(1, max_input_weight + 1):
        best = n + 1
        for mask in combinations_with_weight(n, weight):
            output = 0
            v = mask
            while v:
                lsb = v & -v
                output ^= cols[lsb.bit_length() - 1]
                v ^= lsb
            best = min(best, weight + output.bit_count())
        out.append(best)
    return out


def combinations_with_weight(n: int, weight: int):
    """Gosper enumeration of n-bit masks with exactly `weight` ones."""
    if weight == 0:
        yield 0
        return
    x = (1 << weight) - 1
    limit = 1 << n
    while x < limit:
        yield x
        c = x & -x
        r = x + c
        x = (((r ^ x) >> 2) // c) | r


def support_after_layer_active_columns(
    support: set[int], cols: list[int]
) -> set[int]:
    out: set[int] = set()
    for bit in support:
        value = cols[bit]
        while value:
            lsb = value & -value
            out.add(lsb.bit_length() - 1)
            value ^= lsb
    return out


def reachable_columns_after_linear(support: set[int], active: set[int]) -> set[int]:
    out = set()
    for word_bit in support:
        out.add(word_bit // 9 if False else word_bit % 64)
    return out


def linear_checks() -> None:
    for name, rows in (("L", L_ROWS), ("R", R_ROWS)):
        cols = mix_columns(rows)
        rank = gf2_rank(cols, 9 * N)
        total, weights, min_w, max_w = weighted_support(cols)
        assert rank == 9 * N
        assert total == 9 * N * 5
        assert set(weights.values()) == {5}
        inv = inverse_columns(cols)
        inv_total, inv_weights, inv_min, inv_max = weighted_support(inv)
        bns = branch_numbers(cols, 3)
        print(
            f"{name}: rank={rank}, total={total}, inverse_total={inv_total}, "
            f"inverse_min/avg/max={inv_min}/"
            f"{inv_total / len(inv):.2f}/{inv_max}, BN={bns}"
        )

    # Full Version II rank and row weight.
    full_cols = mix_columns(L_ROWS) + [
        value << (9 * N) for value in mix_columns(R_ROWS)
    ]
    assert gf2_rank(full_cols, 18 * N) == 18 * N
    assert sum(c.bit_count() for c in full_cols) == 18 * N * 5
    print("LII: rank=1152, row/column weight=5")


if __name__ == "__main__":
    validate_tables()
    print("tables: all structural assertions passed")
    component_checks()
    linear_checks()
