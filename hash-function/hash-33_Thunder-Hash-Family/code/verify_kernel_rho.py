#!/usr/bin/env python3
"""Exact GF(2) counterexample to rho(K) = K for pinned Thunder-p.

Coordinates are indexed by 64*(5*y+x)+z, exactly as in the pinned PDF.
The script evaluates theta+I and rho on an explicit 192-bit state v.
"""

TAU = {
    4: [6, 18, 49, 17, 43],
    3: [48, 30, 61, 8, 38],
    2: [34, 5, 0, 2, 37],
    1: [40, 52, 19, 47, 9],
    0: [45, 33, 13, 1, 27],
}
T = [41, 50, 6, 10, 27]
R_SHIFT = 1
S_SHIFT = 36
U_SHIFT = 26


def idx(x: int, y: int, z: int) -> int:
    return 64 * (5 * (y % 5) + (x % 5)) + (z % 64)


def bit(state: int, x: int, y: int, z: int) -> int:
    return (state >> idx(x, y, z)) & 1


def rho(state: int) -> int:
    out = 0
    for x in range(5):
        for y in range(5):
            for z in range(64):
                out |= bit(state, x, y, z + TAU[y][x]) << idx(x, y, z)
    return out


def theta_plus_identity(state: int) -> int:
    """Return theta(state) xor state."""

    def parity_p(x: int, z: int) -> int:
        return sum(bit(state, x, y, z) for y in range(5)) & 1

    def parity_q(x: int, z: int) -> int:
        return sum(bit(state, x, y, z + T[y]) for y in range(5)) & 1

    out = 0
    for x in range(5):
        for y in range(5):
            for z in range(64):
                e = (
                    parity_p(x, z + U_SHIFT)
                    ^ parity_p(x - 1, z + U_SHIFT + R_SHIFT)
                )
                zf = z + U_SHIFT + T[y]
                f = parity_q(x + 1, zf) ^ parity_q(x - 2, zf + S_SHIFT)
                if e ^ f:
                    out ^= 1 << idx(x, y, z)
    return out


def counterexample() -> int:
    state = 0
    for z in range(64):
        if z & 1:
            state |= 1 << idx(0, 0, z)
        state |= 1 << idx(2, 0, z)
        state |= 1 << idx(3, 0, z)
        if not (z & 1):
            state |= 1 << idx(0, 1, z)
    return state


def main() -> None:
    v = counterexample()
    assert v.bit_count() == 192
    assert theta_plus_identity(v) == 0

    rv = rho(v)
    violation = theta_plus_identity(rv)
    assert rv.bit_count() == 192
    assert violation != 0
    assert bit(violation, 1, 0, 1) == 1

    print(f"weight(v) = {v.bit_count()}")
    print(f"(theta+I)(v) weight = {theta_plus_identity(v).bit_count()}")
    print(f"weight(rho(v)) = {rv.bit_count()}")
    print(f"(theta+I)(rho(v)) weight = {violation.bit_count()}")
    print(f"(theta+I)(rho(v))[{idx(1, 0, 1)}] = 1")
    print("v in ker(theta+I), rho(v) not in ker(theta+I)")


if __name__ == "__main__":
    main()
