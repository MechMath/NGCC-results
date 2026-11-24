#!/usr/bin/env python3
"""Exact ANF-degree and reduced-cube checks requested by the handoff."""

from __future__ import annotations

import json
import random
from pathlib import Path

from zc_dmc import chi_column, inverse_chi_column


def anf_monomials(truth: list[int]) -> list[int]:
    """Mobius transform: nonzero masks are exactly the ANF monomials."""
    coeff = truth[:]
    n = len(coeff).bit_length() - 1
    assert len(coeff) == 1 << n
    for bit in range(n):
        step = 1 << bit
        for mask in range(len(coeff)):
            if mask & step:
                coeff[mask] ^= coeff[mask ^ step]
    return [mask for mask, value in enumerate(coeff) if value]


def degree_data(width: int, inverse: bool) -> dict:
    fn = inverse_chi_column if inverse else chi_column
    rows = []
    for output_bit in range(width):
        truth = [
            (fn(x, width) >> output_bit) & 1
            for x in range(1 << width)
        ]
        monomials = anf_monomials(truth)
        rows.append({
            "output_bit": output_bit,
            "degree": max((m.bit_count() for m in monomials), default=0),
            "cubic_masks": [m for m in monomials if m.bit_count() == 3],
            "quartic_masks": [m for m in monomials if m.bit_count() == 4],
        })
    return {
        "width": width,
        "inverse": inverse,
        "coordinate_degrees": [row["degree"] for row in rows],
        "max_degree": max(row["degree"] for row in rows),
        "rows": rows,
    }


def toy_rol(value: int, amount: int, zbits: int) -> int:
    mask = (1 << zbits) - 1
    amount %= zbits
    value &= mask
    return ((value << amount) | (value >> (zbits - amount))) & mask


def toy_round(bits: int, *, zbits: int = 5, lanes: int = 1,
              planes: int = 3) -> int:
    """One zero-constant toy round with the ZC-1536 stage geometry."""
    state = [[0] * lanes for _ in range(planes)]
    p = 0
    for y in range(planes):
        for x in range(lanes):
            state[y][x] = (bits >> p) & ((1 << zbits) - 1)
            p += zbits

    # chi
    out = [[0] * lanes for _ in range(planes)]
    for x in range(lanes):
        for z in range(zbits):
            col = sum(((state[y][x] >> z) & 1) << y for y in range(planes))
            col = chi_column(col, planes)
            for y in range(planes):
                out[y][x] |= ((col >> y) & 1) << z
    state = out

    # rho = rho1; theta; rho2 for the ZC-1536 offsets.
    rhos = ((0, 0), (3, 3), (5, 0))

    def apply_rho(a):
        return [
            [toy_rol(a[y][(x - rhos[y][0]) % lanes], rhos[y][1], zbits)
             for x in range(lanes)]
            for y in range(planes)
        ]

    state = apply_rho(state)
    parity = [
        state[0][x] ^ state[1][x] ^ state[2][x] for x in range(lanes)
    ]
    effect = [
        toy_rol(parity[(x - 1) % lanes], 20, zbits)
        ^ toy_rol(parity[(x - 1) % lanes], 56 % zbits, zbits)
        for x in range(lanes)
    ]
    state = [
        [state[y][x] ^ effect[x] for x in range(lanes)]
        for y in range(planes)
    ]
    state = apply_rho(state)

    result = 0
    p = 0
    for y in range(planes):
        for x in range(lanes):
            result |= state[y][x] << p
            p += zbits
    return result


def apply_toy_rounds(x: int, rounds: int, **kwargs) -> int:
    for _ in range(rounds):
        x = toy_round(x, **kwargs)
    return x


def affine_cube_xor(mapping: list[int], dimension: int, rng: random.Random,
                    output_bits: int) -> tuple[int, list[int]]:
    n = output_bits
    assert dimension <= n
    base = rng.getrandbits(n)
    directions = []
    while len(directions) < dimension:
        v = rng.getrandbits(n)
        if v and all(v.bit_count() != u.bit_count() or v != u
                     for u in directions):
            # Accept linearly independent directions by rank checking below.
            trial = directions + [v]
            pivots = set()
            for u in trial:
                w = u
                while w:
                    p = w.bit_length() - 1
                    if p in pivots:
                        w ^= 1 << p
                    else:
                        pivots.add(p)
                        break
            if len(pivots) == len(trial):
                directions.append(v)
    cube_points = []
    value = 0
    for selector in range(1 << dimension):
        x = base
        for i, direction in enumerate(directions):
            if (selector >> i) & 1:
                x ^= direction
        cube_points.append(x)
        value ^= mapping[x]
    return value, cube_points


def main() -> int:
    result = {
        "chi_anf": {
            "forward_3": degree_data(3, False),
            "inverse_3": degree_data(3, True),
            "forward_5": degree_data(5, False),
            "inverse_5": degree_data(5, True),
        },
        "toy_6_round": {},
    }

    # The toy has 3*1*5 = 15 state bits. Exhaustively tabulate six forward
    # rounds and derive six inverse rounds from the inverse permutation table.
    n = 15
    forward = [apply_toy_rounds(x, 6) for x in range(1 << n)]
    inverse = [0] * (1 << n)
    for x, y in enumerate(forward):
        inverse[y] = x
    assert len(set(forward)) == 1 << n

    def whole_table_max_degree(mapping: list[int]) -> dict:
        degrees = []
        for output_bit in range(n):
            truth = [(mapping[x] >> output_bit) & 1 for x in range(1 << n)]
            coeffs = truth[:]
            for bit in range(n):
                step = 1 << bit
                for mask in range(len(coeffs)):
                    if mask & step:
                        coeffs[mask] ^= coeffs[mask ^ step]
            degrees.append(max(
                (mask.bit_count() for mask, value in enumerate(coeffs) if value),
                default=0,
            ))
        return {
            "coordinate_degrees": degrees,
            "max_degree": max(degrees),
        }

    fdeg = whole_table_max_degree(forward)
    ideg = whole_table_max_degree(inverse)
    rng = random.Random(0xC0BE)
    cube_results = {}
    for name, mapping, degree in (("P6", forward, fdeg["max_degree"]),
                                  ("P-6", inverse, ideg["max_degree"])):
        dimension = degree + 1
        if dimension <= n:
            tests = []
            for _ in range(8):
                value, _points = affine_cube_xor(mapping, dimension, rng, n)
                tests.append(value)
            cube_results[name] = {
                "cube_dimension": dimension,
                "random_cubes": len(tests),
                "xor_values": tests,
                "all_zero": not any(tests),
            }
        else:
            cube_results[name] = {
                "cube_dimension": None,
                "all_zero": None,
                "note": f"degree+1 exceeds the {n}-bit toy state",
            }

    result["toy_6_round"] = {
        "state_bits": n,
        "parameters": {
            "planes": 3,
            "lanes": 1,
            "zbits": 5,
            "theta_z_rotations": [20 % 5, 56 % 5],
            "rho": [[0, 0], [3 % 1, 3 % 5], [5 % 1, 0]],
            "round_constants": "omitted (additive constants do not affect degree)",
        },
        "forward_degree": fdeg,
        "inverse_degree": ideg,
        "cube_sum_checks": cube_results,
    }

    out = Path("artifacts/structural-results.json")
    out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))
    print(f"result_json={out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
