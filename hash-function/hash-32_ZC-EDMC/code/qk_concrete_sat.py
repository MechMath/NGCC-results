#!/usr/bin/env python3
"""Concrete two-copy SAT diagnostic for the six-round ZC Q_K witness."""

import sys
import time

import pycryptosat


CONSTANTS = {
    -11: 0x58, -10: 0x38, -9: 0x3C0, -8: 0xD0, -7: 0x60, -6: 0x120,
    -5: 0x14, -4: 0x2C, -3: 0xF0, -2: 0x1A0, -1: 0x380, 0: 0x12,
}


class Encoder:
    def __init__(self):
        self.next_var = 1
        self.solver = pycryptosat.Solver()

    def new(self):
        v = self.next_var
        self.next_var += 1
        return v

    def clause(self, lits):
        self.solver.add_clause(lits)

    def xor(self, lits, rhs=False):
        """Add XOR(lits) = rhs, normalizing negated literals."""
        parity = int(rhs)
        out = []
        for lit in lits:
            if lit < 0:
                parity ^= 1
            out.append(abs(lit))
        self.solver.add_xor_clause(out, bool(parity))

    def and2(self, a, b):
        t = self.new()
        self.clause([-t, a])
        self.clause([-t, b])
        self.clause([t, -a, -b])
        return t

    def xor_var(self, lits):
        t = self.new()
        self.xor([t] + lits, False)
        return t


def rho(state):
    shifts = [0, 3, 5]
    return [
        [[state[y][(x - shifts[y]) % 8][(z - shifts[y]) % 64]
          for z in range(64)] for x in range(8)]
        for y in range(3)
    ]


def theta(enc, state):
    p = [[enc.xor_var([state[0][x][z], state[1][x][z], state[2][x][z]])
          for z in range(64)] for x in range(8)]
    e = [[enc.xor_var([p[(x - 1) % 8][(z - 5) % 64],
                       p[(x - 1) % 8][(z - 14) % 64]])
          for z in range(64)] for x in range(8)]
    return [[[enc.xor_var([state[y][x][z], e[x][z]]) for z in range(64)]
             for x in range(8)] for y in range(3)]


def chi(enc, state):
    out = []
    for y in range(3):
        row = []
        for x in range(8):
            bits = []
            for z in range(64):
                a = state[y][x][z]
                b = state[(y + 1) % 3][x][z]
                c = state[(y + 2) % 3][x][z]
                bits.append(enc.xor_var([a, enc.and2(~b, ~c)]))
            row.append(bits)
        out.append(row)
    return out


def round_fn(enc, state, rc):
    state = [[list(bits) for bits in row] for row in state]
    for z in range(8):
        if (rc >> z) & 1:
            state[0][0][z] = ~state[0][0][z]
    state = chi(enc, state)
    state = rho(state)
    state = theta(enc, state)
    return rho(state)


def initial(enc, prefix):
    return [[[enc.new() for _ in range(64)] for _ in range(8)]
            for _ in range(3)]


def run_half(enc, state, half_name):
    rounds = range(-11, -5) if half_name == "g" else range(-5, 1)
    for rc in rounds:
        state = round_fn(enc, state, CONSTANTS[rc])
    return state


def serialize(state):
    return [state[y][x][z] for x in range(8) for y in range(3)
            for z in range(64)]


def main():
    half_name = sys.argv[1] if len(sys.argv) > 1 else "g"
    c = int(sys.argv[2]) if len(sys.argv) > 2 else 576
    seed = int(sys.argv[3]) if len(sys.argv) > 3 else 1
    timeout = int(sys.argv[4]) if len(sys.argv) > 4 else 600
    d_lane = int(sys.argv[5]) if len(sys.argv) > 5 else None
    d_value = int(sys.argv[6], 0) if len(sys.argv) > 6 else (1 << 64) - 1
    m = 1536
    r = m - c
    enc = Encoder()
    x = initial(enc, "x")
    y = initial(enc, "y")
    ox = serialize(run_half(enc, x, half_name))
    oy = serialize(run_half(enc, y, half_name))
    ix, iy = serialize(x), serialize(y)
    for t in range(m):
        if t < r:
            enc.xor([ox[t], oy[t]], False)
        else:
            enc.xor([ox[t], oy[t], ix[t], iy[t]], False)
    if d_lane is None:
        diff_vars = [enc.xor_var([ix[t], iy[t]]) for t in range(m)]
        enc.clause(diff_vars)
    else:
        for t in range(m):
            want = ((t // 64 == d_lane) and bool((d_value >> (t % 64)) & 1))
            enc.xor([ix[t], iy[t]], want)
    start = time.time()
    sat, model = enc.solver.solve()
    elapsed = time.time() - start
    print(f"half={half_name} c={c} vars={enc.next_var-1} result={sat} elapsed={elapsed:.3f}s")
    if not sat:
        return

    def value(lit):
        v = model[abs(lit)]
        return bool(v) if lit > 0 else not bool(v)

    def words(state):
        return [[sum((1 if value(state[y][x][z]) else 0) << z
                     for z in range(64))
                 for x in range(8)] for y in range(3)]

    xw, yw, xo, yo = words(x), words(y), words(ox), words(oy)
    # These are lane words in (y,x) layout, not a claimed API encoding.
    print("X_LANES=" + " ".join(f"{v:016x}" for row in xw for v in row))
    print("Y_LANES=" + " ".join(f"{v:016x}" for row in yw for v in row))
    print("KX_LANES=" + " ".join(f"{v:016x}" for row in xo for v in row))
    print("KY_LANES=" + " ".join(f"{v:016x}" for row in yo for v in row))


if __name__ == "__main__":
    main()
