#!/usr/bin/env python3
"""Independent 12-round replay for the ZC-1280 serialization audit."""

ROUND_CONSTANTS = [
    0x0000000000000058,
    0x0000000000000038,
    0x00000000000003C0,
    0x00000000000000D0,
    0x0000000000000060,
    0x0000000000000120,
    0x0000000000000014,
    0x000000000000002C,
    0x00000000000000F0,
    0x00000000000001A0,
    0x0000000000000380,
    0x0000000000000012,
]


def rot_lane(lane: int, amount: int) -> int:
    amount %= 64
    return ((lane << amount) | (lane >> (64 - amount))) & ((1 << 64) - 1)


def permute(state):
    a = state
    for rc in ROUND_CONSTANTS:
        # iota: A_0[0] is y=0, x=0.
        for z in range(64):
            a[0][0][z] ^= (rc >> z) & 1

        # chi is applied independently to every column (x, z).
        b = [[[0] * 64 for _ in range(4)] for _ in range(5)]
        for y in range(5):
            y1 = (y + 1) % 5
            y2 = (y + 2) % 5
            for x in range(4):
                b[y][x] = [
                    (1 - a[y1][x][z]) & a[y2][x][z] for z in range(64)
                ]
        for y in range(5):
            for x in range(4):
                for z in range(64):
                    a[y][x][z] ^= b[y][x][z]

        # rho, encoded from the coordinate formula on page 7.
        old = [[row[:] for row in plane] for plane in a]
        shifts = (0, 5, 24, 1, 3)
        xshifts = (0, 1, 3, 0, 2)
        for y in range(5):
            for x in range(4):
                for z in range(64):
                    a[y][x][z] = old[y][(x - xshifts[y]) % 4][
                        (z - shifts[y]) % 64
                    ]

        # theta, encoded as E[x,z] = P[x-1,z-5] xor P[x-1,z-14].
        p = [[0] * 64 for _ in range(4)]
        for y in range(5):
            for x in range(4):
                for z in range(64):
                    p[x][z] ^= a[y][x][z]
        e = [[0] * 64 for _ in range(4)]
        for x in range(4):
            for z in range(64):
                e[x][z] = p[(x - 1) % 4][(z - 5) % 64] ^ p[
                    (x - 1) % 4
                ][(z - 14) % 64]
        for y in range(5):
            for x in range(4):
                for z in range(64):
                    a[y][x][z] ^= e[x][z]

        # The second rho uses the same coordinate formula.
        old = [[row[:] for row in plane] for plane in a]
        for y in range(5):
            for x in range(4):
                for z in range(64):
                    a[y][x][z] = old[y][(x - xshifts[y]) % 4][
                        (z - shifts[y]) % 64
                    ]
    return a


def serial_positions(order):
    positions = []
    for i in range(1280):
        if order == "A":
            x, rem = divmod(i, 5 * 64)
            y, z = divmod(rem, 64)
        else:
            y, rem = divmod(i, 4 * 64)
            x, z = divmod(rem, 64)
        positions.append((x, y, z))
    return positions


def digest(order):
    pattern = "10110011100011110000111101010101"
    message = pattern * 4
    padding = "01" + "1" + "0" * 572 + "1"
    padded = message + padding
    assert len(padded) == 704
    block = padded + "0" * 576

    positions = serial_positions(order)
    state = [[[0] * 64 for _ in range(4)] for _ in range(5)]
    for bit, (x, y, z) in zip(block, positions):
        state[y][x][z] = int(bit)

    initial = [[row[:] for row in plane] for plane in state]
    transformed = permute(state)
    out = []
    for x, y, z in positions[:512]:
        out.append(str(transformed[y][x][z] ^ initial[y][x][z]))
    return "".join(out)


if __name__ == "__main__":
    da = digest("A")
    db = digest("B")
    print("A prefix", da[:64])
    print("B prefix", db[:64])
    print("different positions", sum(x != y for x, y in zip(da, db)))
    print("A hex", bytes(int(da[i : i + 8], 2) for i in range(0, 512, 8)).hex())
    print("B hex", bytes(int(db[i : i + 8], 2) for i in range(0, 512, 8)).hex())
