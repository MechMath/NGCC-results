#!/usr/bin/env python3
"""Explore literal source-reading alternatives while checking the corrected prefix."""

from itertools import product
import verify_axis_packing as v

EXPECTED = "01100110011111101111101011011111"


def pair_product(bits, pairing):
    return ((bits[pairing[0]] & bits[pairing[1]]) ^
            (bits[pairing[2]] & bits[pairing[3]]) ^
            (bits[pairing[4]] & bits[pairing[5]]))


MATCHINGS = [
    (a, b, c, d, e, f)
    for a in range(6)
    for b in range(a + 1, 6)
    for c in range(6)
    if c not in (a, b)
    for d in range(c + 1, 6)
    if d not in (a, b)
    for e in range(6)
    if e not in (a, b, c, d)
    for f in range(e + 1, 6)
    if f not in (a, b, c, d) and a < c < e
]


def up_res(state, j, m, exl, upl, rot, regdir, tau_pair, self_pair):
    def get(k, i):
        return (state[(j + regdir * k) % 8] >> i) & 1

    tau_bits = [get(5, exl[3]), get(5, exl[2]),
                get(3, exl[5]), get(3, exl[1]),
                get(1, exl[4]), get(1, exl[0])]
    tau = pair_product(tau_bits, tau_pair)
    selected = [exl[5], exl[2], exl[4], exl[1], exl[3], exl[0]]
    sb = pair_product([get(0, i) for i in selected], self_pair)
    new_b = m ^ sb ^ tau ^ get(-1, exl[6])
    t0 = get(0, exl[2]) ^ get(0, exl[1]) ^ get(0, exl[0]) ^ new_b
    t1 = get(0, exl[5]) ^ get(0, exl[4]) ^ get(0, exl[3]) ^ new_b
    reg = state[j]
    for i in (upl[2], upl[1], upl[0]):
        reg ^= t1 << i
    for i in (upl[5], upl[4], upl[3]):
        reg ^= t0 << i
    if rot == "ror":
        state[j] = ((reg >> 1) | (reg << 191)) & v.MASK192
    else:
        state[j] = ((reg << 1) | (reg >> 191)) & v.MASK192


def run(exl, upl, rot, regdir, const_byte_hi, const_seq_hi, c_reverse, message_left,
        init_reverse, tau_pair=(0, 1, 2, 3, 4, 5), self_pair=(0, 1, 2, 3, 4, 5)):
    initial_constants = v.CONSTANTS.copy()
    state = initial_constants.copy()
    if init_reverse:
        initial_constants.reverse()
        state.reverse()
    n = 8
    s = (-n - 3) % 64
    msg = [0] * n + [1] + [0] * (s + 1) + [1] + v.binary64(n)

    def take2():
        if message_left:
            x = (msg[0] << 1) | msg[1]
            del msg[:2]
        else:
            x = (msg[-2] << 1) | msg[-1]
            del msg[-2:]
        return x

    for _ in range(64):
        x = take2()
        order = range(8)
        for j in order:
            up_res(state, j, (x >> 1) if j % 2 == 0 else (x & 1), exl, upl, rot, regdir, tau_pair, self_pair)
    assert not msg

    init_bytes = []
    sequence = list(range(8))
    if const_seq_hi:
        sequence.reverse()
    for r in sequence:
        shifts = list(range(0, 192, 8))
        if const_byte_hi:
            shifts.reverse()
        for s in shifts:
            init_bytes.append((initial_constants[r] >> s) & 0xFF)
    cbytes = (init_bytes * 7)[:1280]
    for byte in cbytes[:1024]:
        for j in range(8):
            cj = ((byte >> (7 - j)) if c_reverse else (byte >> j)) & 1
            up_res(state, j, cj, exl, upl, rot, regdir, tau_pair, self_pair)

    outs = []
    for i in range(256):
        hu = ((state[6] ^ state[4] ^ (state[2] & state[0])) >> 0) & 1
        hv = ((state[7] ^ state[5] ^ (state[3] & state[1])) >> 0) & 1
        outs.append((hu << 1) | hv)
        for j in range(8):
            cj = ((cbytes[1024 + i] >> ((7 - j) if c_reverse else j)) & 1)
            up_res(state, j, cj, exl, upl, rot, regdir, tau_pair, self_pair)
    bits = []
    for x in reversed(outs):
        bits.extend(((x >> 1) & 1, x & 1))
    return "".join(map(str, bits[:32]))


if __name__ == "__main__":
    for flags in product((False, True), repeat=9):
        exl_sem, upl_sem, rot_ror, regplus, byte_hi, seq_hi, c_rev, msg_left, init_rev = flags
        exl = v.EXL if exl_sem else (11, 125, 107, 96, 32, 12, 0)
        upl = v.UPL if upl_sem else (188, 178, 162, 90, 75, 66)
        result = run(exl, upl, "ror" if rot_ror else "rol", 1 if regplus else -1,
                     byte_hi, seq_hi, c_rev, msg_left, init_rev)
        if result == EXPECTED:
            print("MATCH", flags, result)

    for tau_pair in MATCHINGS:
        for self_pair in MATCHINGS:
            result = run(v.EXL, v.UPL, "ror", 1, False, False, False, False, False,
                         tau_pair, self_pair)
            if result == EXPECTED:
                print("PAIR MATCH", tau_pair, self_pair, result)

    print("expected", EXPECTED)
