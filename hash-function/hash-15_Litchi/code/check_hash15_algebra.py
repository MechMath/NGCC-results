#!/usr/bin/env python3
"""Finite checks for the Litchi S-box and Table 4-10 recurrence.

These checks support the explanatory derivation. They are not a run-backed
cryptanalytic experiment and make no claim about the full permutation's exact
multiround degrees beyond the cited upper-bound recurrence.
"""

S = [
    0, 2, 4, 23, 8, 10, 14, 13, 16, 18, 20, 15, 28, 30, 26, 17,
    1, 19, 5, 6, 9, 27, 31, 12, 25, 11, 29, 22, 21, 7, 3, 24,
]


def msb_bits(x: int) -> list[int]:
    return [(x >> (4 - i)) & 1 for i in range(5)]


def msb_int(bits: list[int]) -> int:
    return sum(b << (4 - i) for i, b in enumerate(bits))


def forward_circuit(x: int) -> int:
    a0, a1, a2, a3, a4 = msb_bits(x)
    out = [
        a0 & a2 & a3 ^ a2 & a3 & a4 ^ a0 & a4 ^ a3 & a4 ^ a1,
        a1 & a3 & a4 ^ a0 & a1 ^ a2,
        a1 & a2 ^ a3,
        a2 & a3 ^ a4,
        a3 & a4 ^ a0,
    ]
    return msb_int(out)


def inverse_circuit(y: int) -> int:
    y0, y1, y2, y3, y4 = msb_bits(y)
    out = [
        y0*y1 ^ y1*y2 ^ y0*y1*y3 ^ y2*y3 ^ y4
        ^ y0*y4 ^ y0*y2*y4 ^ y0*y3*y4 ^ y2*y3*y4,
        y0 ^ y3*y4,
        y1 ^ y0*y4 ^ y3*y4,
        y0*y1 ^ y2 ^ y0*y4 ^ y3*y4 ^ y1*y3*y4,
        y0*y1 ^ y1*y2 ^ y3 ^ y0*y4 ^ y0*y2*y4
        ^ y3*y4 ^ y1*y3*y4 ^ y2*y3*y4,
    ]
    return msb_int(out)


def degree_bounds() -> list[int]:
    bounds = [3, 9, 27, 81, 243, 729]
    d = bounds[-1]
    for _ in range(10):
        # Largest integer strictly below
        # 1600 - floor((1599 - d) / 3).
        d = 1600 - ((1599 - d) // 3) - 1
        bounds.append(d)
    return bounds


def main() -> None:
    assert [forward_circuit(x) for x in range(32)] == S
    inv = [0] * 32
    for x, y in enumerate(S):
        inv[y] = x
    assert [inverse_circuit(y) for y in range(32)] == inv
    assert inverse_circuit(2) == 1

    expected = [
        3, 9, 27, 81, 243, 729, 1309, 1503,
        1567, 1589, 1596, 1598, 1599, 1599, 1599, 1599,
    ]
    assert degree_bounds() == expected
    print("S-box/circuit match: OK")
    print("MSB-first inverse ANF match: OK")
    print("Table 4-10 recurrence: OK")


if __name__ == "__main__":
    main()
