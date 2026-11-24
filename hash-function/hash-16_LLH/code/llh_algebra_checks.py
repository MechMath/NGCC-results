#!/usr/bin/env python3
"""Deterministic checks for the scoped LLH S6 algebraic note.

These checks support the written proof but are not a solver run or attack evidence.
"""

from itertools import combinations, product


def ror6(x: int, k: int) -> int:
    return ((x >> k) | (x << (6 - k))) & 0x3F


def s6(x: int) -> int:
    return x ^ ror6(x, 2) ^ (ror6(x, 1) & ror6(x, 3)) ^ 0x1B


def anf(values: list[int]) -> list[tuple[int, int]]:
    """Return (monomial_mask, coefficient) for a 6-bit truth table."""
    coeff = values[:]
    for i in range(6):
        for mask in range(64):
            if mask & (1 << i):
                coeff[mask] ^= coeff[mask ^ (1 << i)]
    return [(mask, value) for mask, value in enumerate(coeff) if value]


def main() -> None:
    table = [s6(x) for x in range(64)]
    assert len(set(table)) == 64

    inverse = [0] * 64
    for x, y in enumerate(table):
        inverse[y] = x

    output_anfs = []
    for bit in range(6):
        terms = anf([(y >> bit) & 1 for y in table])
        output_anfs.append(terms)
        assert max(mask.bit_count() for mask, _ in terms) <= 2

    inverse_degrees = []
    for bit in range(6):
        terms = anf([(inverse[x] >> bit) & 1 for x in range(64)])
        inverse_degrees.append(max(mask.bit_count() for mask, _ in terms))
    assert inverse_degrees == [3] * 6

    differential_uniformity = max(
        sum((table[x] ^ table[x ^ delta]) == out for x in range(64))
        for delta in range(1, 64)
        for out in range(64)
    )
    assert differential_uniformity == 16

    max_walsh = 0
    for in_mask in range(64):
        for out_mask in range(64):
            if in_mask == 0 and out_mask == 0:
                continue
            walsh = sum(
                (1 if ((x & in_mask).bit_count() & 1) == 0 else -1)
                * (1 if ((table[x] & out_mask).bit_count() & 1) == 0 else -1)
                for x in range(64)
            )
            max_walsh = max(max_walsh, abs(walsh))
    assert max_walsh == 32

    # Products in the six coordinate ANFs.  They are precisely two triangles.
    edges = []
    for terms in output_anfs:
        quadratic = [mask for mask, _ in terms if mask.bit_count() == 2]
        assert len(quadratic) == 1
        edges.append(quadratic[0])
    assert set(edges) == {
        (1 << 1) | (1 << 3),
        (1 << 2) | (1 << 4),
        (1 << 3) | (1 << 5),
        (1 << 0) | (1 << 4),
        (1 << 1) | (1 << 5),
        (1 << 0) | (1 << 2),
    }

    covers = []
    for size in range(7):
        for guess in combinations(range(6), size):
            chosen = sum(1 << i for i in guess)
            if all(chosen & edge for edge in edges):
                covers.append(guess)
    assert min(map(len, covers)) == 4
    assert sum(len(c) == 4 for c in covers) == 9

    instances = {
        "LLH-256": {"w": 32, "d": 256, "rounds": 16},
        "LLH-512": {"w": 64, "d": 512, "rounds": 24},
    }
    for name, p in instances.items():
        slices = p["rounds"] * 24 * p["w"]
        pre_vars = p["d"] + slices
        collision_vars = 2 * p["d"] + 2 * slices
        guesses = 4 * 4 * p["w"] * p["rounds"]
        print(
            name,
            {
                "round_state_equations": slices,
                "preimage_variables": pre_vars,
                "preimage_equations": slices + p["d"],
                "collision_variables": collision_vars,
                "collision_round_equations": 2 * slices,
                "collision_output_equations": p["d"],
                "vertex_cover_guess_bits": guesses,
                "S6_product_occurrences": slices,
                "S24_product_occurrences": 3 * slices,
            },
        )

    print("S6 output ANFs:")
    for bit, terms in enumerate(output_anfs):
        rendered = []
        for mask, value in terms:
            factors = [f"x{i}" for i in range(6) if mask & (1 << i)]
            rendered.append("*".join(factors) if factors else "1")
        print(bit, " + ".join(rendered))


if __name__ == "__main__":
    main()
