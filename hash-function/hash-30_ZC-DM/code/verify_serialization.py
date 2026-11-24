#!/usr/bin/env python3
"""Independent local check of the ZC-1280-DM-512 serialization witness."""

MASK64 = (1 << 64) - 1
ROUND_CONSTANTS = [
    0x58, 0x38, 0x3C0, 0xD0, 0x60, 0x120,
    0x14, 0x2C, 0xF0, 0x1A0, 0x380, 0x12,
]
RHO = [(0, 0), (1, 5), (3, 24), (0, 1), (2, 3)]


def rot_lane(value, dz):
    dz %= 64
    if dz == 0:
        return value & MASK64
    return ((value << dz) | (value >> (64 - dz))) & MASK64


def rho(state):
    out = [[0] * 4 for _ in range(5)]
    for y in range(5):
        dx, dz = RHO[y]
        for x in range(4):
            out[y][(x + dx) % 4] ^= rot_lane(state[y][x], dz)
    return out


def theta(state):
    parity = [0] * 4
    for x in range(4):
        parity[x] = state[0][x] ^ state[1][x] ^ state[2][x] ^ state[3][x] ^ state[4][x]
    effect = [0] * 4
    for x in range(4):
        effect[x] = rot_lane(parity[(x - 1) % 4], 5) ^ rot_lane(
            parity[(x - 1) % 4], 14
        )
    return [[state[y][x] ^ effect[x] for x in range(4)] for y in range(5)]


def round_per(state, constant):
    state = [row[:] for row in state]
    state[0][0] ^= constant
    out = [row[:] for row in state]
    for y in range(5):
        out[y] = [
            state[y][x]
            ^ ((~state[(y + 1) % 5][x]) & state[(y + 2) % 5][x])
            for x in range(4)
        ]
    return rho(theta(rho(out)))


def permutation(state):
    for constant in ROUND_CONSTANTS:
        state = round_per(state, constant)
    return state


def bits_to_state(bits, serialization):
    state = [[0] * 4 for _ in range(5)]
    for i, bit in enumerate(bits):
        if bit == "1":
            z = i % 64
            q = i // 64
            if serialization == "A":
                x, y = divmod(q, 5)
            else:
                y, x = divmod(q, 4)
            state[y][x] |= 1 << z
    return state


def state_bits(state, serialization):
    bits = []
    if serialization == "A":
        coordinates = ((x, y) for x in range(4) for y in range(5))
    else:
        coordinates = ((x, y) for y in range(5) for x in range(4))
    for x, y in coordinates:
        bits.extend("1" if (state[y][x] >> z) & 1 else "0" for z in range(64))
    return "".join(bits)


def digest(message, serialization):
    padded = message + "01" + "1" + "0" * 572 + "1"
    assert len(padded) == 704
    state = bits_to_state(padded + "0" * 576, serialization)
    state = permutation(state)
    state = [
        [state[y][x] ^ bits_to_state(padded + "0" * 576, serialization)[y][x]
         for x in range(4)]
        for y in range(5)
    ]
    return state_bits(state, serialization)[:512]


if __name__ == "__main__":
    unit = "10110011100011110000111101010101"
    message = unit * 4
    expected = {
        "A": "1111100111100001100011000001011101110111110111110010011001010010",
        "B": "0111001111100100101100000010011011101111001101011100011110100100",
    }
    for serialization in ("A", "B"):
        result = digest(message, serialization)
        print(serialization, result[:64], result[:64] == expected[serialization])
    left = digest(message, "A")
    right = digest(message, "B")
    print("different_bits", sum(a != b for a, b in zip(left, right)))
