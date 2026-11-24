#!/usr/bin/env python3
"""Independent SAT check of Wish's byte-activity differential bounds."""

from __future__ import annotations

import argparse
import itertools

from pysat.examples.rc2 import RC2
from pysat.formula import WCNF

from wish_structure_check import butterfly


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("lanes", type=int, choices=(8, 16))
    ap.add_argument("rounds", type=int)
    ap.add_argument("--multi-start", action="store_true")
    args = ap.parse_args()

    n = 16 * args.lanes
    mix = butterfly(args.lanes, (1, 2, 8) if args.lanes == 8 else (1, 2, 4, 8))
    wcnf = WCNF()
    top = 1000000

    def var(prefix: str, r: int, i: int) -> int:
        return 1 + (r * n + i) * 2 + (0 if prefix == "x" else 1)

    # Exactly byte 0 is active initially unless explicitly searching arbitrary
    # initial differentials. Wish's AES/Mix schedule is position transitive under
    # one AES round, and this is the minimum-activity convention used by Table 5/6.
    if not args.multi_start:
        wcnf.append([var("x", 0, 0)])
        for i in range(1, n):
            wcnf.append([-var("x", 0, i)])
    else:
        wcnf.append([var("x", 0, i) for i in range(n)])

    for r in range(args.rounds):
        def sr_input(i: int) -> int:
            lane, within = divmod(i, 16)
            row, col = within % 4, within // 4
            return lane * 16 + row + 4 * ((col - row) % 4)

        for col in range(4 * args.lanes):
            ins = [var("x", r, sr_input(4 * col + t)) for t in range(4)]
            outs = [var("z", r, 4 * col + t) for t in range(4)]
            bits = ins + outs
            for vals in itertools.product((False, True), repeat=8):
                tin = sum(vals[:4])
                tout = sum(vals[4:])
                valid = ((tin == 0) == (tout == 0)) and (
                    tin == 0 or tin + tout >= 5
                )
                if not valid:
                    # Forbid this pattern.
                    wcnf.append(
                        [(-lit if bit else lit) for lit, bit in zip(bits, vals)]
                    )
        # Mix occurs once per Step, after the second AES round (r odd), not
        # between the two AES rounds of a Step.
        if r + 1 < args.rounds and r % 2 == 1:
            for i in range(n):
                a, b = var("x", r + 1, i), var("z", r, mix[i])
                wcnf.append([-a, b])
                wcnf.append([a, -b])
        elif r + 1 < args.rounds:
            for i in range(n):
                a, b = var("x", r + 1, i), var("z", r, i)
                wcnf.append([-a, b])
                wcnf.append([a, -b])

    for r in range(args.rounds):
        for i in range(n):
            wcnf.append([-var("x", r, i)], weight=1)

    with RC2(wcnf, solver="cadical195") as rc2:
        model = rc2.compute()
        print("active_total", rc2.cost)
        if model is not None:
            truth = set(model)
            print(
                "active_sbox_inputs_by_round",
                [
                    [i for i in range(n) if var("x", r, i) in truth]
                    for r in range(args.rounds)
                ],
            )


if __name__ == "__main__":
    main()
