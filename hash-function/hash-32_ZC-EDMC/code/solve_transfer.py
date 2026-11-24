#!/usr/bin/env python3
"""Symbolic search for three capacity-zero states with XOR-zero P outputs."""

from __future__ import annotations

import argparse
import json
import time

from z3 import BitVec, BitVecVal, Solver, Or, sat

RC = [0x58, 0x38, 0x3C0, 0xD0, 0x60, 0x120, 0x14, 0x2C, 0xF0, 0x1A0, 0x380, 0x12]


def roll64(x, n):
    n %= 64
    return x if n == 0 else ((x << n) | (x >> (64 - n)))


def ror64(x, n):
    n %= 64
    return x if n == 0 else ((x >> n) | (x << (64 - n)))


def lane_index(xdim: int, x: int, y: int) -> int:
    return x * (5 if xdim == 4 else 3) + y


def rho(state, xdim, inverse=False):
    planes = 5 if xdim == 4 else 3
    offsets = [(0, 0), (1, 5), (3, 24), (0, 1), (2, 3)]
    if planes == 3:
        offsets = [(0, 0), (3, 3), (5, 0)]
    out = [None] * len(state)
    for x in range(xdim):
        for y in range(planes):
            dx, dz = offsets[y]
            src_x = (x + dx) % xdim if inverse else (x - dx) % xdim
            w = state[lane_index(xdim, src_x, y)]
            out[lane_index(xdim, x, y)] = roll64(w, dz) if inverse else ror64(w, dz)
    return out


def chi(state, xdim):
    planes = 5 if xdim == 4 else 3
    out = state[:]
    for x in range(xdim):
        a = [state[lane_index(xdim, x, y)] for y in range(planes)]
        b = [(~a[(i + 1) % planes]) & a[(i + 2) % planes] for i in range(planes)]
        for y in range(planes):
            out[lane_index(xdim, x, y)] = a[y] ^ b[y]
    return out


def theta(state, xdim):
    planes = 5 if xdim == 4 else 3
    dx, dz1 = (1, 5) if planes == 5 else (1, 20)
    dz2 = 14 if planes == 5 else 56
    parity = []
    for x in range(xdim):
        p = BitVecVal(0, 64)
        for y in range(planes):
            p = p ^ state[lane_index(xdim, x, y)]
        parity.append(p)
    effect = [
        ror64(parity[(x - dx) % xdim], dz1) ^ ror64(parity[(x - dx) % xdim], dz2)
        for x in range(xdim)
    ]
    out = state[:]
    for x in range(xdim):
        for y in range(planes):
            i = lane_index(xdim, x, y)
            out[i] = state[i] ^ effect[x]
    return out


def round_fn(state, xdim, c):
    state = state[:]
    state[0] = state[0] ^ BitVecVal(c, 64)
    state = chi(state, xdim)
    state = rho(state, xdim)
    state = theta(state, xdim)
    return rho(state, xdim)


def permute(state, xdim):
    for c in RC:
        state = round_fn(state, xdim, c)
    return state


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--m", type=int, choices=(1280, 1536), default=1536)
    ap.add_argument("--c", type=int, default=1088)
    ap.add_argument("--timeout-ms", type=int, default=300000)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    xdim = 4 if args.m == 1280 else 8
    planes = 5 if xdim == 4 else 3
    lanes = xdim * planes
    assert args.m == lanes * 64
    rate_lanes = (args.m - args.c) // 64
    assert rate_lanes * 64 == args.m - args.c

    s = Solver()
    s.set(timeout=args.timeout_ms)
    states = []
    for k in range(3):
        st = [BitVec(f"s{k}_{i}", 64) for i in range(lanes)]
        for i in range(rate_lanes, lanes):
            s.add(st[i] == 0)
        states.append(st)
    ys = [permute(st, xdim) for st in states]
    for i in range(lanes):
        s.add(ys[0][i] ^ ys[1][i] ^ ys[2][i] == 0)
    ## Avoid the trivial all-equal solution.
    s.add(Or(*[states[0][i] != states[1][i] for i in range(rate_lanes)]))

    t0 = time.time()
    status = s.check()
    result = {
        "m": args.m,
        "c": args.c,
        "r": args.m - args.c,
        "status": str(status),
        "seconds": time.time() - t0,
        "reason_unknown": s.reason_unknown() if status != sat and status != sat else "",
    }
    if status == sat:
        model = s.model()
        values = [[model.eval(w).as_long() for w in st] for st in states]
        result["states"] = values
        result["distinct"] = values[0] != values[1] and values[0] != values[2] and values[1] != values[2]
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)
    print(json.dumps({k: v for k, v in result.items() if k != "states"}, indent=2))


if __name__ == "__main__":
    main()
