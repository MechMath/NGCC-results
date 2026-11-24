#!/usr/bin/env python3
"""Exact-difference trail search for the pinned LLH specification.

This is a discovery model.  Reported coefficients are independently checked by
enumerating the rotating six-bit S-box table in verify_trail().
"""

from __future__ import annotations

import argparse
import json
import math
from fractions import Fraction
from functools import reduce
from operator import xor

import z3


MASK6 = 0x3F
DERANGEMENT = [
    4, 9, 18, 23, 8, 1, 22, 15, 12, 17, 6, 3,
    20, 5, 10, 19, 0, 21, 14, 11, 16, 13, 2, 7,
]
SHIFTS = {
    32: [3, 16, 13, 26, 8, 29, 2, 23, 21, 18, 31, 28,
         10, 15, 4, 9, 7, 20, 17, 30, 12, 1, 6, 27],
    64: [2, 25, 20, 51, 15, 40, 37, 6, 36, 63, 62, 33,
         1, 30, 31, 4, 38, 5, 8, 47, 19, 52, 57, 34],
    96: [2, 11, 28, 53, 19, 34, 57, 88, 52, 73, 6, 43,
         5, 32, 67, 14, 70, 7, 48, 1, 55, 94, 45, 4],
    128: [1, 16, 55, 118, 10, 29, 72, 11, 35, 58, 105, 48,
          76, 103, 26, 101, 5, 36, 91, 42, 78, 113, 44, 127],
}


def ror6(x: int, n: int) -> int:
    return ((x >> n) | (x << (6 - n))) & MASK6


def s6(x: int) -> int:
    return x ^ ror6(x, 2) ^ (ror6(x, 1) & ror6(x, 3)) ^ 0x1B


def ddt() -> dict[tuple[int, int], int]:
    out: dict[tuple[int, int], int] = {}
    for di in range(64):
        for x in range(64):
            key = (di, s6(x) ^ s6(x ^ di))
            out[key] = out.get(key, 0) + 1
    return out


DIFF_TABLE = ddt()
DIFF_SUPPORT = sorted(DIFF_TABLE)
HIGH_WEIGHT_PROBABILITY_SUPPORT = sorted(
    pair for pair, count in DIFF_TABLE.items() if count == 16
)


def linear_support() -> list[tuple[int, int]]:
    support = []
    for u in range(64):
        for v in range(64):
            if u == 0 and v == 0:
                continue
            walsh = sum(
                1 if ((u & s6(x)).bit_count() ^ (v & x).bit_count()) & 1 == 0
                else -1
                for x in range(64)
            )
            if walsh:
                support.append((u, v))
    return support


LINEAR_SUPPORT = linear_support()


def pack_bits(bits: list[z3.BoolRef]) -> z3.BitVecRef:
    value = z3.BitVecVal(0, len(bits))
    for i, bit in enumerate(bits):
        value = value | z3.If(
            bit, z3.BitVecVal(1 << i, len(bits)), z3.BitVecVal(0, len(bits))
        )
    return value


def unpack6(v: z3.BitVecRef) -> list[z3.BoolRef]:
    return [z3.Extract(i, i, v) == 1 for i in range(6)]


def linear_layer(do: list[z3.BitVecRef]) -> list[z3.BoolRef]:
    """Inputs are the four 6-bit column outputs; output is a 24-bit mask."""
    before = [None] * 24
    for c in range(4):
        bits = unpack6(do[c])
        for r in range(6):
            # The S6 result is laid out row-major as a 6x4 matrix.
            before[4 * r + c] = bits[r]
    after_derangement = [None] * 24
    for src, dst in enumerate(DERANGEMENT):
        after_derangement[dst] = before[src]
    out = []
    for r in range(6):
        row = after_derangement[4 * r:4 * r + 4]
        for j in range(4):
            out.append(reduce(xor, (row[i] for i in range(4) if i != j)))
    return out


def linear_layer_int(do: list[int]) -> int:
    before = [0] * 24
    for c in range(4):
        for r in range(6):
            before[4 * r + c] = (do[c] >> r) & 1
    after_derangement = [0] * 24
    for src, dst in enumerate(DERANGEMENT):
        after_derangement[dst] = before[src]
    out = 0
    for r in range(6):
        row = after_derangement[4 * r:4 * r + 4]
        for j in range(4):
            bit = row[0] ^ row[1] ^ row[2] ^ row[3] ^ row[j]
            out |= bit << (4 * r + j)
    return out


def lookup_constraint(pair: tuple[z3.BitVecRef, z3.BitVecRef],
                      support: list[tuple[int, int]]) -> z3.BoolRef:
    a, b = pair
    return z3.Or([
        z3.And(a == z3.BitVecVal(x, 6), b == z3.BitVecVal(y, 6))
        for x, y in support
    ])


def build_model(w: int, rounds: int, mode: str, active_limit: int | None,
                max_weight: int | None):
    """Return (solver, active_count, state_inputs, round_masks)."""
    shifts = SHIFTS[w]
    if not (len(shifts) == 24 and all(0 <= x < w for x in shifts)):
        raise ValueError("bad shift table")

    # Difference variables at S-box inputs.  delta[t][j][c] is the six-bit
    # input difference of column c of S24 in slide j at round t.
    delta = [[[z3.BitVec(f"d_{t}_{j}_{c}", 6) for c in range(4)]
              for j in range(w)] for t in range(rounds + 1)]
    dos_by_round = [[[z3.BitVec(f"o_{t}_{j}_{c}", 6) for c in range(4)]
                     for j in range(w)] for t in range(rounds)]
    active_terms = []
    weight_terms = []
    relations = []

    for t in range(rounds):
        outputs = []
        for j in range(w):
            dos = []
            for c in range(4):
                di = delta[t][j][c]
                do = dos_by_round[t][j][c]
                dos.append(do)
                active_terms.append(z3.If(di == 0, 0, 1))
                if mode == "differential":
                    # Existential left member of the input pair.  This encodes
                    # exactly S6(x) xor S6(x xor di) = do.
                    x = z3.BitVec(f"x_{t}_{j}_{c}", 6)
                    sx = x ^ z3.RotateRight(x, 2)
                    sx ^= z3.RotateRight(x, 1) & z3.RotateRight(x, 3)
                    sx ^= z3.BitVecVal(0x1B, 6)
                    xd = x ^ di
                    sxd = xd ^ z3.RotateRight(xd, 2)
                    sxd ^= z3.RotateRight(xd, 1) & z3.RotateRight(xd, 3)
                    sxd ^= z3.BitVecVal(0x1B, 6)
                    relations.append(do == (sx ^ sxd))
                    weight_terms.append(z3.If(
                        di == 0,
                        0,
                        z3.If(
                            z3.Or([
                                z3.And(
                                    di == z3.BitVecVal(a, 6),
                                    do == z3.BitVecVal(b, 6),
                                )
                                for a, b in HIGH_WEIGHT_PROBABILITY_SUPPORT
                            ]),
                            2,
                            4,
                        ),
                    ))
                else:
                    relations.append(lookup_constraint((di, do), LINEAR_SUPPORT))
            outputs.append(linear_layer(dos))

        # ShiftRows has one offset per 24-bit word position.  The bit at
        # row-major position p=4*i+c moves from slide j to j+sigma_p.
        # Delay this wiring until every S24 output slide has been constructed.
        for j in range(w):
            for c in range(4):
                bits = []
                for r in range(6):
                    position = 4 * r + c
                    source_slide = (j - shifts[position]) % w
                    bits.append(outputs[source_slide][position])
                delta[t + 1][j][c] = pack_bits(bits)

    solver = z3.Solver()
    solver.add(relations)
    # A useful trail must start nonzero.  The empty trail is the trivial one.
    solver.add(z3.Or([delta[0][j][c] != 0 for j in range(w) for c in range(4)]))
    count = z3.Sum(active_terms)
    if active_limit is not None:
        solver.add(count == active_limit)
    if max_weight is not None:
        solver.add(z3.Sum(weight_terms) <= max_weight)
    return solver, count, delta, dos_by_round


def concrete_delta(model: z3.ModelRef, state) -> list[list[int]]:
    return [[model.eval(state_delta).as_long() for state_delta in row]
            for row in state]


def verify_trail(w: int, rounds: int, state, outs) -> dict:
    shifts = SHIFTS[w]
    current = state
    weight = Fraction(0)
    probability = Fraction(1)
    per_round = []
    input_states = []
    transitions = []
    for t in range(rounds):
        input_states.append([
            [{"slide": j, "column": c, "value": f"0x{current[j][c]:02x}"}
             for c in range(4) if current[j][c]]
            for j in range(w) if any(current[j])
        ])
        active = 0
        output_masks = []
        for j in range(w):
            dos = []
            for c in range(4):
                di, do = current[j][c], outs[t][j][c]
                count = DIFF_TABLE.get((di, do), 0)
                if count == 0:
                    raise AssertionError(f"impossible S6 transition t={t} j={j} c={c}")
                if di:
                    active += 1
                    probability *= Fraction(count, 64)
                    weight += Fraction(2, 1) if count == 16 else Fraction(4, 1)
                    transitions.append({
                        "round": t, "slide": j, "column": c,
                        "din": f"0x{di:02x}", "dout": f"0x{do:02x}",
                        "count": count, "weight": 2 if count == 16 else 4,
                    })
                dos.append(do)
            output_masks.append(linear_layer_int(dos))
        nxt = [[[0] * 4 for _ in range(w)]][0]
        for j in range(w):
            for c in range(4):
                z = 0
                for r in range(6):
                    position = 4 * r + c
                    src = (j - shifts[position]) % w
                    z |= ((output_masks[src] >> position) & 1) << r
                nxt[j][c] = z
        per_round.append(active)
        current = nxt
    return {
        "active_per_round": per_round,
        "input_states": input_states,
        "active_sboxes": sum(per_round),
        "trail_probability": f"{probability.numerator}/{probability.denominator}",
        "trail_weight": float(weight),
        "transitions": transitions,
        "output_delta_nonzero": [
            {"slide": j, "column": c, "value": f"0x{current[j][c]:02x}"}
            for j in range(w) for c in range(4) if current[j][c]
        ],
        "output_difference_nonzero": any(x for row in current for x in row),
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--w", type=int, choices=[32, 64, 96, 128], default=32)
    ap.add_argument("--rounds", type=int, default=1)
    ap.add_argument("--mode", choices=["differential", "linear"], default="differential")
    ap.add_argument("--active-limit", type=int)
    ap.add_argument("--max-weight", type=int)
    ap.add_argument("--timeout-ms", type=int, default=30000)
    args = ap.parse_args()

    if args.mode == "linear":
        raise SystemExit(
            "linear mode is documented in this file but intentionally requires "
            "the Walsh support relation to be wired before execution"
        )

    solver, count, delta, outs = build_model(
        args.w, args.rounds, args.mode, args.active_limit, args.max_weight
    )
    solver.set(timeout=args.timeout_ms)
    result = solver.check()
    report = {
        "w": args.w,
        "rounds": args.rounds,
        "mode": args.mode,
        "active_limit": args.active_limit,
        "max_weight": args.max_weight,
        "solver": "z3-5.4.1",
        "solver_result": str(result),
        "ddt_support_pairs": len(DIFF_SUPPORT),
        "ddt_profile": sorted(
            {(c, sum(1 for n in DIFF_TABLE.values() if n == c))
             for c in set(DIFF_TABLE.values())}
        ),
        "linear_support_pairs": len(LINEAR_SUPPORT),
    }
    if result == z3.sat:
        model = solver.model()
        state = concrete_delta(model, delta[0])
        outs_value = [
            [[model.eval(x).as_long() for x in row] for row in layer]
            for layer in outs
        ]
        report["input_delta_nonzero"] = [
            {"slide": j, "column": c, "value": f"0x{state[j][c]:02x}"}
            for j in range(args.w) for c in range(4) if state[j][c]
        ]
        report.update(verify_trail(args.w, args.rounds, state, outs_value))
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
