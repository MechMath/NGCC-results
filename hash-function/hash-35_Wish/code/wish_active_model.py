#!/usr/bin/env python3
"""Bit-activity model for one nonzero byte entering a Wish permutation.

This checks selected printed Table 5/6 entries, and can emit a concrete activity
trail for independent replay.  Z3 is used only as a local search aid here; the
emitted trail is subsequently checked directly against every permitted transition.
"""

from __future__ import annotations

import argparse

from z3 import Bool, If, Int, Optimize, Or, Sum, sat

from wish_structure_check import butterfly


def model(lanes: int, rounds: int):
    n = 16 * lanes
    mix = butterfly(lanes, (1, 2, 8) if lanes == 8 else (1, 2, 4, 8))
    x = [[Bool(f"x_{r}_{i}") for i in range(n)] for r in range(rounds)]
    z = [[Bool(f"z_{r}_{i}") for i in range(n)] for r in range(rounds)]
    opt = Optimize()
    opt.add(x[0][0])
    for r in range(rounds):
        # ShiftRows then MixColumns. ShiftRows is a bijection, so MC input at
        # byte i is the S-box-output activity at the inverse ShiftRows position.
        def sr_input(i: int) -> int:
            lane, within = divmod(i, 16)
            row, col = within % 4, within // 4
            return lane * 16 + row + 4 * ((col - row) % 4)

        for col in range(4 * lanes):
            ins = [x[r][sr_input(4 * col + t)] for t in range(4)]
            outs = [z[r][4 * col + t] for t in range(4)]
            tin = Sum([If(v, 1, 0) for v in ins])
            tout = Sum([If(v, 1, 0) for v in outs])
            any_in = Or(*ins)
            any_out = Or(*outs)
            # AES MixColumns has differential branch number 5.  This is the
            # standard byte-activity relaxation used by the claimed MILP model.
            opt.add(any_out == any_in)
            opt.add(tin + tout >= If(any_in, 5, 0))
        if r + 1 < rounds:
            for i in range(n):
                opt.add(x[r + 1][i] == z[r][mix[i]])
    opt.minimize(Sum([If(v, 1, 0) for row in x for v in row]))
    return opt, x, z


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("lanes", type=int, choices=(8, 16))
    ap.add_argument("rounds", type=int)
    args = ap.parse_args()
    opt, x, z = model(args.lanes, args.rounds)
    if opt.check() != sat:
        print("UNSAT")
        return
    m = opt.model()
    trail = []
    for row in x:
        trail.append([i for i, v in enumerate(row) if m.eval(v, model_completion=True)])
    print("active_total", sum(map(len, trail)))
    print("active_sbox_inputs_by_round", trail)


if __name__ == "__main__":
    main()
