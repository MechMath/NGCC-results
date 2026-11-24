#!/usr/bin/env python3
"""Exact Duet active-support search for a few rounds, encoded as CNF+XOR.

A real S-box is a bijection, and every nonzero input difference has at least
one nonzero output difference.  The support abstraction therefore imposes
only: a 5-bit output difference is zero exactly when its input difference is
zero.  This is exact for the active-S-box objective, but it deliberately does
not select DDT weights.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import signal
import time
from pathlib import Path

from pysat.card import CardEnc, EncType
from pysat.formula import CNF, IDPool
from pysat.solvers import Solver


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


def matrix(width: int) -> list[list[int]]:
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


def flat_state(vars_: list[list[list[int]]], width: int) -> list[int]:
    """State bits in word order X_(0,0),...,X_(4,0),X_(0,1),... ."""
    return [
        vars_[i][j][k]
        for j in range(width // 320)
        for i in range(5)
        for k in range(64)
    ]


def linear(variables: IDPool, x: list[list[list[int]]], width: int,
           prefix: str) -> tuple[list[list[list[int]]], list[list[int]]]:
    xs = flat_state(x, width)
    blo = width // 64
    mat = matrix(blo)
    cnf = CNF()
    ms = []
    for i in range(blo):
        out_var = []
        for k in range(64):
            z = variables.id(f"{prefix}_ms_{i}_{k}")
            terms = [xs[j * 64 + k] for j, bit in enumerate(mat[i]) if bit]
            # z = XOR(terms), as parity clauses.
            for mask in range(1 << len(terms)):
                clause = [z if mask.bit_count() % 2 == 0 else -z]
                for p, term in enumerate(terms):
                    clause.append(term if (mask >> p) & 1 else -term)
                cnf.append(clause)
            out_var.append(z)
        ms.append(out_var)
    y = [[[None] * 64 for _ in range(width // 320)] for _ in range(5)]
    for t in range(blo):
        j, i = divmod(t, 5)
        for k in range(64):
            z = variables.id(f"{prefix}_ml_{j}_{i}_{k}")
            terms = [
                ms[t][(k - t) % 64],
                ms[t][(k - t - 21) % 64],
                ms[t][(k - t - 43) % 64],
            ]
            for mask in range(8):
                clause = [z if mask.bit_count() % 2 == 0 else -z]
                for p, term in enumerate(terms):
                    clause.append(term if (mask >> p) & 1 else -term)
                cnf.append(clause)
            y[i][j][k] = z
    return y, cnf.clauses


def solve(width: int, rounds: int, max_active: int, timeout: int):
    m = width // 320
    variables = IDPool()
    cnf = CNF()
    active_all = []
    active_layers = []
    state_layers = []

    x = [[[variables.id(f"x0_{i}_{j}_{k}") for k in range(64)]
          for j in range(m)] for i in range(5)]
    state_layers.append(x)
    for r in range(rounds):
        outgoing = [[[None] * 64 for _ in range(m)] for _ in range(5)]
        layer_active = []
        for j in range(m):
            for k in range(64):
                inbits = [x[i][j][k] for i in range(5)]
                outbits = [
                    variables.id(f"y{r}_{j}_{k}_{i}") for i in range(5)
                ]
                a = variables.id(f"a{r}_{j}_{k}")
                layer_active.append(a)
                active_all.append(a)
                cnf.append([-a] + outbits)
                for b in outbits:
                    cnf.append([-b, a])
                for b in outbits:
                    cnf.append([-b] + inbits)
                for b in inbits:
                    cnf.append([-b] + outbits)
                for i in range(5):
                    outgoing[i][j][k] = outbits[i]
        active_layers.append(layer_active)
        x, linear_clauses = linear(variables, outgoing, width, f"r{r}")
        cnf.extend(linear_clauses)
        state_layers.append(x)

    cnf.append(active_all)
    card = CardEnc.atmost(
        lits=active_all, bound=max_active, vpool=variables, encoding=EncType.seqcounter
    )
    cnf.extend(card.clauses)
    start = time.monotonic()
    timed_out = False
    def alarm(_signum, _frame):
        raise TimeoutError

    previous = signal.signal(signal.SIGALRM, alarm)
    signal.setitimer(signal.ITIMER_REAL, timeout)
    try:
        with Solver(name="cadical195", bootstrap_with=cnf.clauses) as solver:
            solver.set_phases([-v for v in range(1, variables.top + 1)])
            status = solver.solve()
            model = set(v for v in solver.get_model() if v > 0) if status else set()
    except TimeoutError:
        timed_out = True
        status = None
        model = set()
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)
    elapsed = time.monotonic() - start
    result = {
        "width": width,
        "rounds": rounds,
        "max_active": max_active,
        "status": "budget_exhausted" if timed_out else ("sat" if status else "unsat"),
        "elapsed_seconds": elapsed,
        "variables": variables.top,
        "clauses": len(cnf.clauses),
        "active_sboxes_per_S_layer": [
            sum(a in model for a in layer) for layer in active_layers
        ] if status else [],
        "encoded_active_sboxes": len(active_all),
        "round_convention": "SC support, M15/M30, then ML; AC is zero in differences.",
        "active_abstraction": (
            "For each cell, the 5-bit S-box output difference is zero iff "
            "the input difference is zero; all nonzero outputs are permitted."
        ),
        "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    }
    return result


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--width", type=int, choices=[960, 1920], required=True)
    ap.add_argument("--rounds", type=int, required=True)
    ap.add_argument("--max-active", type=int, required=True)
    ap.add_argument("--timeout", type=int, default=60)
    ap.add_argument("--output")
    args = ap.parse_args()
    text = json.dumps(solve(
        args.width, args.rounds, args.max_active, args.timeout
    ), indent=2, sort_keys=True)
    print(text)
    if args.output:
        Path(args.output).write_text(text + "\n")


if __name__ == "__main__":
    main()
