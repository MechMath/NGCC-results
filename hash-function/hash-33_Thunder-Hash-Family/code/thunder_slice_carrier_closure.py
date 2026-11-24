#!/usr/bin/env python3
"""Close local 0/31 slice constraints under L-transpose."""

from thunder_fixedspace import linear, pos


def add_basis(basis, value):
    while value:
        p = value.bit_length() - 1
        if p in basis:
            value ^= basis[p]
        else:
            basis[p] = value
            return True
    return False


def main():
    # rows[j] is L^T applied to output coordinate j, represented as an
    # input-coordinate functional.
    rows = [0] * 1600
    for i in range(1600):
        value = linear(1 << i)
        while value:
            low = value & -value
            j = low.bit_length() - 1
            rows[j] |= 1 << i
            value ^= low

    # L commutes with global z rotation, so z=0 represents all 64 shifts for
    # each x. The five x positions cover all 320 S-box slices.
    for x in range(5):
        ps = [pos(x, y, 0) for y in range(5)]
        basis = {}
        frontier = []
        for y in range(1, 5):
            delta = (1 << ps[0]) ^ (1 << ps[y])
            add_basis(basis, delta)
            frontier.append(delta)
        while frontier:
            next_frontier = []
            for delta in frontier:
                value = delta
                image = 0
                while value:
                    low = value & -value
                    j = low.bit_length() - 1
                    image ^= rows[j]
                    value ^= low
                if add_basis(basis, image):
                    next_frontier.append(image)
            frontier = next_frontier
        print("x", x, "closure_dim", len(basis))
        assert len(basis) >= 1597


if __name__ == "__main__":
    main()
