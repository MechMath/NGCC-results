"""Heuristic search for explicit full-round differential trails.

Every returned transition is checked against the exact S-box DDT and the exact
linear layer.  The heuristic itself proves no lower bound.
"""

from __future__ import annotations

import heapq
import math
import random
from dataclasses import dataclass

from thunder_ref import TAU, TY, theta


MASK64 = (1 << 64) - 1


def coords_from_int(value):
    for x in range(5):
        for y in range(5):
            lane = (value >> (64 * (5 * y + x))) & MASK64
            while lane:
                bit = lane & -lane
                z = bit.bit_length() - 1
                yield x, y, z
                lane ^= bit


def int_from_coords(coords):
    out = 0
    for x, y, z in coords:
        out ^= 1 << (64 * (5 * y + x) + z)
    return out


def linear_layer(value):
    state = [[(value >> (64 * (5 * y + x))) & MASK64 for y in range(5)]
             for x in range(5)]
    state = [[((state[x][y] >> TAU[y][x])
               | (state[x][y] << (64 - TAU[y][x])))
              & MASK64 if TAU[y][x] else state[x][y]
              for y in range(5)] for x in range(5)]
    state = theta(state)
    permuted = [[0] * 5 for _ in range(5)]
    for x in range(5):
        for y in range(5):
            permuted[y][(2 * x + 3 * y + 2) % 5] = state[x][y]
    out = 0
    for x in range(5):
        for y in range(5):
            out |= permuted[x][y] << (64 * (5 * y + x))
    return out


LINEAR_COLUMNS = [linear_layer(1 << bit) for bit in range(1600)]


def linear_mask(value):
    out = 0
    while value:
        bit = value & -value
        out ^= LINEAR_COLUMNS[bit.bit_length() - 1]
        value ^= bit
    return out


def sbox(value):
    a = [(value >> i) & 1 for i in range(5)]
    b = [
        a[(i + 3) % 5]
        ^ ((1 ^ a[(i + 1) % 5])
           & a[(i + 2) % 5]
           & (1 ^ a[(i + 4) % 5]))
        for i in range(5)
    ]
    return sum(bit << i for i, bit in enumerate(b))


DDT = [[0] * 32 for _ in range(32)]
for _a in range(32):
    for _x in range(32):
        DDT[_a][sbox(_x) ^ sbox(_x ^ _a)] += 1


def slice_options(value):
    """Return (linear-block, weight, output-value) options for every active slice."""
    groups = []
    for x in range(5):
        for z in range(64):
            a = 0
            for y in range(5):
                a |= ((value >> (64 * (5 * y + x) + z)) & 1) << y
            if not a:
                continue
            options = []
            for b, count in enumerate(DDT[a]):
                if not count:
                    continue
                block = 0
                for y in range(5):
                    if (b >> y) & 1:
                        block |= 1 << (64 * (5 * y + x) + z)
                options.append(
                    (linear_mask(block), math.log2(32 / count), b)
                )
            groups.append(((x, z), a, options))
    return groups


@dataclass(frozen=True)
class Trail:
    weight: float
    difference: int
    after_psi: tuple[int, ...]


def children(trail, rng, cap):
    groups = slice_options(trail.difference)
    full_count = math.prod(len(group[2]) for group in groups)
    if full_count <= cap:
        partial = [(0, trail.weight, ())]
        for _, _, options in groups:
            partial = [
                (block ^ b, weight + w, path + (out,))
                for block, weight, path in partial
                for b, w, out in options
            ]
        candidates = partial
    else:
        # Stochastic exploration plus the maximum-DDT transition at each slice.
        selected = []
        greedy = [
            min(options, key=lambda option: option[1])
            for _, _, options in groups
        ]
        selected.append(greedy)
        for _ in range(cap - 1):
            selected.append(
                [rng.choices(options, weights=[2 ** (-w) for _, w, _ in options])[0]
                 for _, _, options in groups]
            )
        candidates = []
        for choices in selected:
            block = 0
            weight = trail.weight
            out_values = []
            for choice in choices:
                b, w, out = choice
                block ^= b
                weight += w
                out_values.append(out)
            candidates.append((block, weight, tuple(out_values)))
    return [
        Trail(weight, diff, after)
        for diff, weight, after in candidates
    ]


def search(rounds=12, beam=8, seed=0xBEEF):
    start = int_from_coords(
        {(2, 0, 41), (2, 0, 55), (2, 2, 26),
         (2, 2, 61), (2, 3, 4), (2, 3, 25)}
    )
    frontier = [Trail(0.0, start, ())]
    rng = random.Random(seed)
    for round_index in range(rounds):
        expanded = []
        for trail in frontier:
            expanded.extend(children(trail, rng, cap=max(32, beam * 6)))
        # A trail's cost is its DDT weight, with active bits and active slices as
        # conservative tie-breakers for future cancellations.
        expanded.sort(
            key=lambda trail: (
                trail.weight,
                trail.difference.bit_count(),
                len(slice_options(trail.difference)),
            )
        )
        best = expanded[0]
        print(
            round_index + 1,
            f"weight={best.weight:.3f}",
            f"bits={best.difference.bit_count()}",
            f"slices={len(slice_options(best.difference))}",
            f"candidates={len(expanded)}",
            flush=True,
        )
        frontier = expanded[:beam]
    return frontier[0]


if __name__ == "__main__":
    trail = search()
    print("FINAL", trail.weight, trail.difference.bit_count(), trail.after_psi)
