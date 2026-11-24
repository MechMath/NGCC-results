#!/usr/bin/env python3
"""Exact reachable XOR-difference support for the WChain Version I core."""

from __future__ import annotations

N = 64
PI = (0, 7, 5, 3, 1, 8, 6, 4, 2)
ROWS = (
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


def bit(lane: int, z: int) -> int:
    return lane * N + z


def chi(x: int) -> int:
    a = [(x >> i) & 1 for i in range(9)]
    b = [
        a[i] ^ ((a[(i + 1) % 9] ^ 1) & a[(i + 2) % 9])
        for i in range(9)
    ]
    return sum(v << i for i, v in enumerate(b))


def make_output_rows(rows_table=ROWS, lane_offset: int = 0) -> list[int]:
    """Return row i as the set of L5w(i) input positions."""
    rows = [0] * (18 * N)
    for out_lane, table_row in enumerate(rows_table):
        for in_lane, rot in table_row:
            for z in range(N):
                rows[bit(in_lane + lane_offset, z)] |= 1 << bit(
                    out_lane + lane_offset, (z + rot) % N
                )
    return rows


def make_ddt_reachable() -> dict[int, int]:
    """For input difference mask a, union every possible output difference."""
    out: dict[int, int] = {}
    for a in range(1, 1 << 9):
        mask = 0
        for x in range(1 << 9):
            mask |= chi(x) ^ chi(x ^ a)
        out[a] = mask
    return out


ROWS_OUT = make_output_rows()
R_ROWS_OUT = make_output_rows(R_ROWS, 9)
DDT_REACHABLE = make_ddt_reachable()


def one_round(support: set[int]) -> set[int]:
    # Nonlinear layer, independently in every z-column. Keep every output
    # difference that can occur for at least one pair with the input difference.
    after_chi: set[int] = set()
    for z in range(N):
        a = 0
        for lane in range(9):
            if bit(lane, z) in support:
                a |= 1 << lane
        b = DDT_REACHABLE.get(a, 0)
        for lane in range(9):
            if (b >> lane) & 1:
                after_chi.add(bit(PI[lane], z))

    # Reachable support after the linear restriction: union the output rows of
    # every source position that can be active.
    image = 0
    for source in after_chi:
        image |= ROWS_OUT[source]
    return {i for i in range(9 * N) if (image >> i) & 1}


def v2_one_round(support: set[int]) -> set[int]:
    after_chi: set[int] = set()
    for z in range(N):
        for half in range(2):
            offset = 9 * half
            a = 0
            for lane in range(9):
                if bit(lane + offset, z) in support:
                    a |= 1 << lane
            b = DDT_REACHABLE.get(a, 0)
            for lane in range(9):
                if (b >> lane) & 1:
                    after_chi.add(bit(PI[lane] + offset, z))

    # CrossSwap5 exchanges these five lane pairs and fixes all other lanes.
    pairs = ((0, 0), (1, 3), (3, 1), (4, 4), (6, 6))
    after_swap: set[int] = set()
    paired_left = {left for left, _right in pairs}
    paired_right = {right for _left, right in pairs}
    for x in after_chi:
        lane, z = divmod(x, N)
        half, local = divmod(lane, 9)
        moved = False
        for left, right in pairs:
            if half == 0 and local == left:
                after_swap.add(bit(9 + right, z))
                moved = True
                break
            if half == 1 and local == right:
                after_swap.add(bit(left, z))
                moved = True
                break
        if not moved:
            assert (half == 0 and local not in paired_left) or (
                half == 1 and local not in paired_right
            )
            after_swap.add(x)

    image = 0
    for source in after_swap:
        table = ROWS_OUT if source < 9 * N else R_ROWS_OUT
        image |= table[source]
    return {i for i in range(18 * N) if (image >> i) & 1}


def v2_profile(support: set[int]) -> tuple[int, int, int, int]:
    return (
        len(support),
        len({x // N for x in support}),
        len({((x // N) // 9, x % N) for x in support}),
        len({x % N for x in support}),
    )


def profile(support: set[int]) -> tuple[int, int, int]:
    return (
        len(support),
        len({x // N for x in support}),
        len({x % N for x in support}),
    )


def main() -> None:
    per_start = []
    for lane in range(9):
        support = {bit(lane, 0)}
        rounds = []
        for _ in range(4):
            support = one_round(support)
            rounds.append(profile(support))
        per_start.append(rounds)
        print(lane, rounds)

    minima = tuple(
        min(per_start[lane][round_index][axis] for lane in range(9))
        for round_index in range(4)
        for axis in range(3)
    )
    print("componentwise minima:", minima)

    v2_per_start = []
    for lane in range(18):
        support = {bit(lane, 0)}
        rounds = []
        for _ in range(4):
            support = v2_one_round(support)
            rounds.append(v2_profile(support))
        v2_per_start.append(rounds)
        print("v2", lane, rounds)
    v2_minima = tuple(
        min(v2_per_start[lane][round_index][axis] for lane in range(18))
        for round_index in range(4)
        for axis in range(4)
    )
    print("v2 componentwise minima:", v2_minima)


if __name__ == "__main__":
    main()
