#!/usr/bin/env python3
"""Diagnostic SMT search for the ZC-EDMC six-round Q_K witness.

This is exploration code.  A SAT result is not execution evidence unless the
witness is independently replayed and recorded through the run machinery.
"""

import sys
import time

import z3


MASK64 = (1 << 64) - 1

CONSTANTS = {
    -11: 0x58,
    -10: 0x38,
    -9: 0x3C0,
    -8: 0xD0,
    -7: 0x60,
    -6: 0x120,
    -5: 0x14,
    -4: 0x2C,
    -3: 0xF0,
    -2: 0x1A0,
    -1: 0x380,
    0: 0x12,
}


def rotlane(a, amount):
    amount %= 8
    if amount == 0:
        return a
    return a[amount:] + a[:amount]


def rho(a):
    return [
        list(a[0]),
        rotlane(a[1], 3),
        rotlane(a[2], 5),
    ]


def theta(a):
    p = []
    for x in range(8):
        p.append(a[0][x] ^ a[1][x] ^ a[2][x])
    e = []
    for x in range(8):
        v = z3.RotateLeft(p[(x - 1) % 8], 20)
        v ^= z3.RotateLeft(p[(x - 1) % 8], 56)
        e.append(v)
    return [[a[y][x] ^ e[x] for x in range(8)] for y in range(3)]


def chi(a):
    out = []
    for y in range(3):
        out.append([
            a[y][x] ^ (~a[(y + 1) % 3][x] & a[(y + 2) % 3][x])
            for x in range(8)
        ])
    return out


def iota(a, rc):
    out = [list(row) for row in a]
    out[0][0] ^= rc
    return out


def round_fn(a, rc):
    a = iota(a, rc)
    a = chi(a)
    a = rho(a)
    a = theta(a)
    a = rho(a)
    return a


def half(a, rounds):
    for rc in rounds:
        a = round_fn(a, CONSTANTS[rc])
    return a


def serialize_lanes(a):
    # API bit t=64*(8*x+y)+z.  Return lane words in increasing t.
    return [a[y][x] for x in range(8) for y in range(3)]


def make_symbolic_state(prefix):
    return [
        [z3.BitVec(f"{prefix}_x{x}_y{y}", 64) for x in range(8)]
        for y in range(3)
    ]


def solve(rate_lanes, half_name, timeout_ms):
    x = make_symbolic_state("x")
    d = make_symbolic_state("d")
    xd = [[x[y][ix] ^ d[y][ix] for ix in range(8)] for y in range(3)]

    if half_name == "g":
        rounds = range(-11, -5)
    elif half_name == "h":
        rounds = range(-5, 1)
    else:
        raise ValueError(half_name)

    xo = half(x, rounds)
    xdo = half(xd, rounds)
    ox = serialize_lanes(xo)
    od = serialize_lanes(xdo)

    solver = z3.Solver()
    solver.set(timeout=timeout_ms)
    nonzero = False
    for i, lane_diff in enumerate(od):
        if i < rate_lanes:
            solver.add(lane_diff == 0)
        else:
            # Capacity output difference must equal the capacity input
            # difference. d is stored as [plane][x], so recover its lane.
            ix = i // 3
            iy = i % 3
            solver.add(lane_diff == d[iy][ix])
    for row in d:
        for lane in row:
            nonzero = z3.Or(nonzero, lane != 0)
    solver.add(nonzero)

    start = time.time()
    result = solver.check()
    elapsed = time.time() - start
    print(f"half={half_name} rate_lanes={rate_lanes} result={result} elapsed={elapsed:.3f}s")
    if result == z3.sat:
        model = solver.model()
        xs = [model.eval(lane, model_completion=True).as_long() for lane in serialize_lanes(x)]
        ds = [model.eval(lane, model_completion=True).as_long() for lane in serialize_lanes(d)]

        def byte_hex(words):
            return "".join(w.to_bytes(8, "little").hex() for w in words)

        print("X_HEX=" + byte_hex(xs))
        print("D_HEX=" + byte_hex(ds))
        print("Y_HEX=" + byte_hex([a ^ b for a, b in zip(xs, ds)]))
        print("KX_HEX=" + byte_hex([model.eval(l, model_completion=True).as_long() for l in ox]))
        print("KY_HEX=" + byte_hex([model.eval(l, model_completion=True).as_long() for l in serialize_lanes(xdo)]))
        return True
    return False


if __name__ == "__main__":
    name = sys.argv[1] if len(sys.argv) > 1 else "g"
    rate_lanes = int(sys.argv[2]) if len(sys.argv) > 2 else 15
    timeout_ms = int(sys.argv[3]) if len(sys.argv) > 3 else 300000
    solve(rate_lanes, name, timeout_ms)
