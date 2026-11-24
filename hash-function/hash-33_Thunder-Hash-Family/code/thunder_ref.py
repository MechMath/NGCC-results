"""Small, direct reference model of the pinned Thunder specification.

The model stores D[x][y] as a 64-bit integer, with bit z of the integer
representing D[x][y][z].  It is intended for structural checks, not as a
performance implementation.
"""

TAU = (
    (45, 33, 13, 1, 27),
    (40, 52, 19, 47, 9),
    (34, 5, 0, 2, 37),
    (48, 30, 61, 8, 38),
    (6, 18, 49, 17, 43),
)
# TAU is indexed [y][x] in the display above.
TY = (41, 50, 6, 10, 27)
RC = (
    0x0000000000000001,
    0x0000000000000003,
    0x000000000000000A,
    0x0000000000000088,
    0x0000000000008081,
    0x0000000000008002,
    0x0000000000000009,
    0x0000000000000083,
    0x000000000000800A,
    0x0000000000000089,
    0x0000000000008083,
    0x000000000000800B,
)


def xor_y(values):
    out = 0
    for value in values:
        out ^= value
    return out


def ror64(value, amount):
    amount %= 64
    if amount == 0:
        return value
    return ((value >> amount) | (value << (64 - amount))) & ((1 << 64) - 1)


def theta(state):
    p = [[xor_y(state[x][y] for y in range(5)) for _ in range(1)]
         for x in range(5)]
    q = [[xor_y(ror64(state[x][y], TY[y]) for y in range(5)) for _ in range(1)]
         for x in range(5)]
    e = [[p[x][0] ^ ror64(p[(x - 1) % 5][0], 1) for _ in range(1)]
         for x in range(5)]
    f = [[q[(x + 1) % 5][0] ^ ror64(q[(x - 2) % 5][0], 36)
          for _ in range(1)] for x in range(5)]
    out = [[0] * 5 for _ in range(5)]
    for x in range(5):
        for y in range(5):
            out[x][y] = (
                state[x][y]
                ^ ror64(e[x][0], 26)
                ^ ror64(f[x][0], 26 + TY[y])
            )
    return out


def round_function(state, round_index):
    # iota
    state = [[state[x][y] for y in range(5)] for x in range(5)]
    state[0][0] ^= RC[round_index]
    # rho: D'[x][y][z] = D[x][y][z + tau(x,y)].
    state = [[ror64(state[x][y], TAU[y][x]) for y in range(5)]
             for x in range(5)]
    state = theta(state)
    # pi: D'[y][2x+3y+2][z] = D[x][y][z].
    permuted = [[0] * 5 for _ in range(5)]
    for x in range(5):
        for y in range(5):
            permuted[y][(2 * x + 3 * y + 2) % 5] = state[x][y]
    state = permuted
    # psi, independently for each fixed (x,z).
    out = [[0] * 5 for _ in range(5)]
    for x in range(5):
        for z in range(64):
            a = [(state[x][y] >> z) & 1 for y in range(5)]
            b = [
                a[(y + 3) % 5]
                ^ ((1 ^ a[(y + 1) % 5])
                   & a[(y + 2) % 5]
                   & (1 ^ a[(y + 4) % 5]))
                for y in range(5)
            ]
            for y in range(5):
                out[x][y] |= b[y] << z
    return out


def permutation(state, rounds=12):
    for round_index in range(rounds):
        state = round_function(state, round_index)
    return state


def state_from_int(value):
    return [[(value >> (64 * (5 * y + x))) & ((1 << 64) - 1)
             for y in range(5)] for x in range(5)]


def state_to_int(state):
    value = 0
    for x in range(5):
        for y in range(5):
            value |= state[x][y] << (64 * (5 * y + x))
    return value
