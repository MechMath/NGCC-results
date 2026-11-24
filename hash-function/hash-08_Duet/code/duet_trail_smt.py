#!/usr/bin/env python3
"""Exact small-round Duet active-S-box feasibility with Z3.

The S-box is a permutation and every nonzero input difference has nonzero
output differences.  Thus its complete differential-support abstraction is
the relation (input cell == 0) iff (output cell == 0).  Actual DDT weights
are not imposed here; this script only tests active-S-box floors.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import time
from pathlib import Path

import z3


SBOX = [
    0x1A, 0x09, 0x10, 0x17, 0x07, 0x08, 0x15, 0x0E,
    0x19, 0x1F, 0x1E, 0x0C, 0x1B, 0x01, 0x04, 0x0A,
    0x05, 0x13, 0x0D, 0x0F, 0x16, 0x1C, 0x06, 0x18,
    0x11, 0x12, 0x14, 0x03, 0x1D, 0x02, 0x00, 0x0B,
]

M15_ROWS = """
1 0 0 1 1 1 0 1 1 0 0 0 0 1 0
0 1 0 0 1 1 1 0 1 1 0 0 0 0 1
1 0 1 0 0 1 1 1 0 1 1 0 0 0 0
0 1 0 1 0 0 1 1 1 0 1 1 0 0 0
0 0 1 0 1 0 0 1 1 1 0 1 1 0 0
0 0 0 1 0 1 0 0 1 1 1 0 1 1 0
0 0 0 0 1 0 1 0 0 1 1 1 0 1 1
1 0 0 0 0 1 0 1 0 0 1 1 1 0 1
1 1 0 0 0 0 1 0 1 0 0 1 1 1 0
0 1 1 0 0 0 0 1 0 1 0 0 1 1 1
1 0 1 1 0 0 0 0 1 0 1 0 0 1 1
1 1 0 1 1 0 0 0 0 1 0 1 0 0 1
1 1 1 0 1 1 0 0 0 0 1 0 1 0 0
0 1 1 1 0 1 1 0 0 0 0 1 0 1 0
0 0 1 1 1 0 1 1 0 0 0 0 1 0 1
"""

M30_FIRST = [
    1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1,
    1, 1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0,
]


def matrices(width: int) -> list[list[int]]:
    if width == 15:
        return [
            [int(x) for x in line.split()]
            for line in M15_ROWS.splitlines()
            if line.strip()
        ]
    return [
        [M30_FIRST[(j - i) % 30] for j in range(30)]
        for i in range(30)
    ]


def sbox_output(prefix: str, x: list[list[z3.BitVecRef]], round_index: int):
    m = len(x[0])
    cons = []
    active = []
    y_bits = [[[] for _ in range(m)] for _ in range(5)]
    for j in range(m):
        for k in range(64):
            xin = z3.Concat(*[
                z3.Extract(k, k, x[row][j]) for row in range(5)
            ])
            yout = z3.BitVec(f"{prefix}_y_r{round_index}_{j}_{k}", 5)
            cons.append((yout == 0) == (xin == 0))
            active.append(yout != 0)
            for i in range(5):
                # yout = y0 || y1 || y2 || y3 || y4, matching the
                # specification's row ordering; place bit yi in row i.
                y_bits[i][j].append(z3.Extract(4 - i, 4 - i, yout))
    y = [[z3.Concat(*y_bits[i][j]) for j in range(m)] for i in range(5)]
    return y, cons, active


def linear_layer(x: list[list[z3.BitVecRef]], width: int):
    m = width // 320
    mat = matrices(width // 64)
    words = [x[i][j] for j in range(m) for i in range(5)]
    ms = []
    for i in range(width // 64):
        term = z3.BitVecVal(0, 64)
        for j, bit in enumerate(mat[i]):
            if bit:
                term = term ^ words[j]
        ms.append(term)
    out = [[None] * m for _ in range(5)]
    for t in range(width // 64):
        z = (
            z3.RotateLeft(ms[t], t)
            ^ z3.RotateLeft(ms[t], (t + 21) % 64)
            ^ z3.RotateLeft(ms[t], (t + 43) % 64)
        )
        j, i = divmod(t, 5)
        out[i][j] = z
    return out


def model_hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def solve(width: int, rounds: int, max_active: int, timeout_ms: int):
    m = width // 320
    x = [[z3.BitVec(f"state_r0_{i}_{j}", 64)
          for j in range(m)] for i in range(5)]
    cons = []
    active = []
    active_layers = []
    input_layers = []
    layers = []
    for r in range(rounds):
        input_layers.append(x)
        y, c, a = sbox_output("duet", x, r)
        cons.extend(c)
        active.extend(a)
        active_layers.append(a)
        layers.append({"S": len(a)})
        x = linear_layer(y, width)
    # Rule out the all-zero trail explicitly.
    cons.append(z3.Or(*active))
    if max_active >= 0:
        cons.append(z3.PbLe([(a, 1) for a in active], max_active))
    solver = z3.Solver()
    solver.set(timeout=timeout_ms)
    solver.add(*cons)
    start = time.monotonic()
    status = solver.check()
    elapsed = time.monotonic() - start
    result = {
        "width": width,
        "rounds": rounds,
        "max_active": max_active,
        "status": str(status),
        "elapsed_seconds": elapsed,
        "encoded_active_sboxes": len(active),
        "round_convention": "Each round is SC support, M15/M30, then ML; AC is absent from differences.",
        "active_abstraction": (
            "For every 5-bit cell, output difference is zero iff input "
            "difference is zero. Every nonzero output value is permitted."
        ),
    }
    if status == z3.sat:
        model = solver.model()
        counts = [
            sum(z3.is_true(model.eval(a, model_completion=True)) for a in layer)
            for layer in active_layers
        ]
        active_indices = [
            [i for i, a in enumerate(layer)
             if z3.is_true(model.eval(a, model_completion=True))]
            for layer in active_layers
        ]
        input_active = []
        for xlayer in input_layers:
            nactive = 0
            for j in range(m):
                for k in range(64):
                    xc = z3.Concat(*[
                        z3.Extract(k, k, xlayer[row][j])
                        for row in range(5)
                    ])
                    nactive += int(
                        str(model.eval(xc, model_completion=True))
                    ) != 0
            input_active.append(nactive)
        result["active_sboxes_per_S_layer"] = counts
        result["input_active_sboxes_recount"] = input_active
        result["active_sbox_indices_flat"] = active_indices
        result["active_sboxes_total"] = sum(counts)
        result["model_available"] = True
    else:
        result["model_available"] = False
    return result


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--width", type=int, choices=[960, 1920], required=True)
    ap.add_argument("--rounds", type=int, required=True)
    ap.add_argument("--max-active", type=int, required=True)
    ap.add_argument("--timeout-ms", type=int, default=30000)
    args = ap.parse_args()
    result = solve(args.width, args.rounds, args.max_active, args.timeout_ms)
    result["script_sha256"] = model_hash(Path(__file__))
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
