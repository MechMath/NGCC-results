#!/usr/bin/env python3
"""Exploratory SMT checks for the PDF's sequential AXIS update."""

from __future__ import annotations

import argparse

from z3 import BitVec, BitVecVal, Extract, If, Or, RotateRight, Solver, sat, unsat

from axis_sim import CONSTANTS, EXL, UPL


def sbox6(z, positions, regs):
    # Concatenation is high-to-low; positions are likewise high-to-low except
    # the self expression, which is supplied already as low-to-high.
    bits = [Extract(p % 192, p % 192, regs[p // 192]) for p in positions]
    return (bits[5] & bits[4]) ^ (bits[3] & bits[2]) ^ (bits[1] & bits[0])


def beat(regs, msg, cb, sequential):
    old = list(regs)
    out = list(regs)
    for j in range(8):
        cur = out if sequential else old
        a, b, c = (j + 5) % 8, (j + 3) % 8, (j + 1) % 8
        tau = sbox6(None, [a * 192 + EXL[3], a * 192 + EXL[2],
                          b * 192 + EXL[5], b * 192 + EXL[1],
                          c * 192 + EXL[4], c * 192 + EXL[0]], cur)
        self_nl = sbox6(None, [j * 192 + EXL[5], j * 192 + EXL[2],
                              j * 192 + EXL[4], j * 192 + EXL[1],
                              j * 192 + EXL[3], j * 192 + EXL[0]], cur)
        preceding = Extract(EXL[6], EXL[6], cur[(j - 1) % 8])
        if cb is None:
            m = Extract(j & 1, j & 1, msg)
        else:
            m = BitVecVal((cb >> j) & 1, 1)
        control = m ^ self_nl ^ tau ^ preceding
        t0 = Extract(EXL[2], EXL[2], cur[j]) ^ Extract(
            EXL[1], EXL[1], cur[j]) ^ Extract(EXL[0], EXL[0], cur[j]) ^ control
        t1 = Extract(EXL[5], EXL[5], cur[j]) ^ Extract(
            EXL[4], EXL[4], cur[j]) ^ Extract(EXL[3], EXL[3], cur[j]) ^ control
        value = cur[j]
        for p in UPL[0:3]:
            value = value ^ If(t1 == 1, BitVecVal(1 << p, 192), 0)
        for p in UPL[3:6]:
            value = value ^ If(t0 == 1, BitVecVal(1 << p, 192), 0)
        out[j] = RotateRight(value, 1)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--concurrent", action="store_true")
    ap.add_argument("--timeout", type=int, default=30000)
    args = ap.parse_args()
    x = [BitVec(f"x{j}", 192) for j in range(8)]
    y = [BitVec(f"y{j}", 192) for j in range(8)]
    msg = BitVec("msg", 2)
    f_x = beat(x, msg, None, not args.concurrent)
    f_y = beat(y, msg, None, not args.concurrent)
    s = Solver()
    s.set(timeout=args.timeout)
    s.add(Or([x[j] != y[j] for j in range(8)]))
    s.add([f_x[j] == f_y[j] for j in range(8)])
    result = s.check()
    print(result, s.reason_unknown() if result not in (sat, unsat) else "")
    if result == sat:
        model = s.model()
        print("x", [hex(model.eval(v, model_completion=True).as_long()) for v in x])
        print("y", [hex(model.eval(v, model_completion=True).as_long()) for v in y])
        print("msg", model.eval(msg, model_completion=True))


if __name__ == "__main__":
    main()
