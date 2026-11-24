#!/usr/bin/env python3
"""Check the round-0 ShiftRow conflict from equation (4).

This is a transcription check, not a cryptographic run or an attack.
"""

from itertools import product


EXAMPLE = (0, 1, 2, 3)
TABLE_3_ROUND_0 = (0, 14, 20, 22)


def shift_row(word: dict[tuple[int, int, int], int], constants: tuple[int, ...]):
    out = {}
    for x, y, z in product(range(4), range(4), range(128)):
        rho = constants[y]
        out[x, y, z] = word[x, y, (z - rho) % 128]
    return out


def external_index(x: int, y: int, z: int) -> int:
    return (4 * x + y) * 128 + z


def main() -> None:
    word = {
        (x, y, z): int(z == 0)
        for x, y, z in product(range(4), range(4), range(128))
    }
    example = shift_row(word, EXAMPLE)
    table = shift_row(word, TABLE_3_ROUND_0)

    differing = [
        (x, y, z)
        for x, y, z in product(range(4), range(4), range(128))
        if example[x, y, z] != table[x, y, z]
    ]

    moved_pairs = []
    for x in range(4):
        for y in range(1, 4):
            moved_pairs.append((x, y, EXAMPLE[y], TABLE_3_ROUND_0[y]))

    expected_entries = [
        (x, y, z)
        for x, y, example_z, table_z in moved_pairs
        for z in (example_z, table_z)
    ]
    assert sorted(differing) == sorted(expected_entries)
    assert len(moved_pairs) == 12
    assert len(differing) == 24

    for x in range(4):
        entries = []
        for y in range(1, 4):
            entries.append(
                (
                    external_index(x, y, EXAMPLE[y]),
                    external_index(x, y, TABLE_3_ROUND_0[y]),
                )
            )
        print(f"x={x}: {entries}")

    print("12 moved one-hot bits; exactly 24 differing state entries")


if __name__ == "__main__":
    main()
