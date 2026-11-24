#!/usr/bin/env python3
"""Independent Litchi round/mode audit from the clean public specification."""

MASK64 = (1 << 64) - 1
ROUND_PARAMS = (
    (31, 1, 4, 21, 22),
    (19, 12, 15, 34, 13),
    (28, 35, 58, 9, 23),
    (55, 18, 5, 27, 44),
    (14, 43, 53, 20, 25),
)
ROUND_CONSTANTS = (
    0xB7E151628AED2A6A, 0xAF82A3CD15DAD4D7, 0x9F4546922BB529AD,
    0xFECA8C2C576AD359, 0x3DD51950AED526B1, 0x7BAA32A15DAA4D62,
    0xF7546542BB549AC4, 0x2EE8CB8D76A9B58B, 0x5DD1971AED536B16,
    0xBBA32E35DAA6D62C, 0xB7065D63B54D2C5B, 0xAE4CBBCF6A9AD8B5,
    0x9CD97696D5353169, 0xF9F2EC25AA6AE2D1, 0x33A5D94354D545A1,
    0x674BB286A9AA8B42,
)
SBOX = (
    0, 2, 4, 23, 8, 10, 14, 13, 16, 18, 20, 15, 28, 30, 26, 17,
    1, 19, 5, 6, 9, 27, 31, 12, 25, 11, 29, 22, 21, 7, 3, 24,
)


def rol(x, n):
    return ((x << n) | (x >> (64 - n))) & MASK64


def ror(x, n):
    return ((x >> n) | (x << (64 - n))) & MASK64


def lanes(state):
    return tuple((state >> (64 * (24 - i))) & MASK64 for i in range(25))


def from_lanes(ws):
    state = 0
    for word in ws:
        state = (state << 64) | word
    return state


def theta_lane(ws, shifts):
    e = ws[0] ^ ws[1] ^ ws[2] ^ ws[3] ^ ws[4]
    f = 0
    for word, shift in zip(ws, shifts):
        f ^= rol(word, shift)
    return tuple(word ^ ror(e, shift) ^ f for word, shift in zip(ws, shifts))


def theta(state):
    ws = list(lanes(state))
    for plane, shifts in enumerate(ROUND_PARAMS):
        start = 5 * plane
        ws[start:start + 5] = theta_lane(ws[start:start + 5], shifts)
    return from_lanes(ws)


def chi(state):
    ws = list(lanes(state))
    for j in range(5):
        a0, a1, a2, a3, a4 = (ws[5 * i + j] for i in range(5))
        b4 = (a3 & a4) ^ a0
        b3 = (a2 & a3) ^ a4
        b2 = (a1 & a2) ^ a3
        b1 = (a1 & a3 & a4) ^ (a0 & a1) ^ a2
        b0 = (a0 & a2 & a3) ^ (a2 & a3 & a4) ^ (a0 & a4) ^ (a3 & a4) ^ a1
        for i, value in enumerate((b0, b1, b2, b3, b4)):
            ws[5 * i + j] = value
    return from_lanes(ws)


def pi_equation(state):
    """Page 7: B[i,j] <- A[(i+2j) mod 5, (3i+3j) mod 5]."""
    old = lanes(state)
    new = [0] * 25
    for i in range(5):
        for j in range(5):
            src = ((i + 2 * j) % 5) * 5 + (3 * i + 3 * j) % 5
            new[5 * i + j] = old[src]
    return from_lanes(new)


def pi_property_matrix(state):
    """Page 13's alternative 'corresponds to' matrix M_src_to_dst=[[1,2],[3,3]]."""
    old = lanes(state)
    new = [0] * 25
    for i in range(5):
        for j in range(5):
            dst = ((i + 2 * j) % 5) * 5 + (3 * i + 3 * j) % 5
            new[dst] = old[5 * i + j]
    return from_lanes(new)


def round_fn(state, round_index, pi):
    state ^= ROUND_CONSTANTS[round_index] << (64 * 15)  # lane 0 = A[0][0]
    return pi(theta(chi(state)))


def permute(state, pi):
    for r in range(16):
        state = round_fn(state, r, pi)
    return state


def litchi_512_empty(pi):
    c, rate = 576, 1024
    padded_empty = 1 << (rate - 1)
    state = padded_empty ^ (c << 0)  # S_0 = [c]_1600 for fid=0
    state = permute(state, pi)
    st = state ^ padded_empty ^ 1  # final rate block and [1]_c
    out_block = (permute(st, pi) & ((1 << c) - 1)) ^ (st & ((1 << c) - 1))
    return out_block >> (c - 512)


def active_lanes(state):
    return [(i // 5, i % 5) for i, word in enumerate(lanes(state)) if word]


def check_sbox_formula():
    for x in range(32):
        a0, a1, a2, a3, a4 = ((x >> k) & 1 for k in (4, 3, 2, 1, 0))
        b0 = (a0 & a2 & a3) ^ (a2 & a3 & a4) ^ (a0 & a4) ^ (a3 & a4) ^ a1
        b1 = (a1 & a3 & a4) ^ (a0 & a1) ^ a2
        b2 = (a1 & a2) ^ a3
        b3 = (a2 & a3) ^ a4
        b4 = (a3 & a4) ^ a0
        y = (b0 << 4) | (b1 << 3) | (b2 << 2) | (b3 << 1) | b4
        assert y == SBOX[x]


def main():
    check_sbox_formula()
    assert len(set(SBOX)) == 32
    single_lane = from_lanes((0,) * 5 + (1,) + (0,) * 19)  # A[1][0]
    assert pi_equation(single_lane) != pi_property_matrix(single_lane)
    print("single-lane witnesses for A[1][0]=1:")
    print(" page 7 equation active lanes:",
          active_lanes(pi_equation(single_lane)))
    print(" page 13 matrix active lanes:  ",
          active_lanes(pi_property_matrix(single_lane)))
    print("Litchi-512(empty) equation pi:")
    print(f" {litchi_512_empty(pi_equation):0128x}")
    print("Litchi-512(empty) property-matrix pi:")
    print(f" {litchi_512_empty(pi_property_matrix):0128x}")


if __name__ == "__main__":
    main()
