#!/usr/bin/env python3
"""CNF active-cell model of the Duet differential DDT-support relaxation."""

from __future__ import annotations

import argparse
import json
import time

from pysat.card import CardEnc, EncType
from pysat.formula import CNF
from pysat.solvers import Glucose3

from exact_duet_support import M15_ROW, M30_ROW, circulant


class Encoder:
    def __init__(self) -> None:
        self.cnf = CNF()
        self.top = 0

    def new(self) -> int:
        self.top += 1
        return self.top

    def add(self, *lits: int) -> None:
        self.cnf.append(list(lits))

    def equiv_xor(self, out: int, xs: list[int]) -> None:
        acc = xs[0]
        for x in xs[1:]:
            nxt = self.new()
            # nxt == acc XOR x
            self.add(-acc, -x, -nxt)
            self.add(acc, x, -nxt)
            self.add(acc, -x, nxt)
            self.add(-acc, x, nxt)
            acc = nxt
        self.add(-out, acc)
        self.add(out, -acc)

    def or_equiv(self, out: int, xs: list[int]) -> None:
        self.add(-out, *xs)
        for x in xs:
            self.add(-x, out)


def build(row: list[int], rounds: int, bound: int) -> tuple[Encoder, list[list[list[int]]], list[int]]:
    enc = Encoder()
    m = len(row) // 5
    layers = [
        [[enc.new() for _ in range(64)] for _ in range(len(row))]
        for _ in range(rounds)
    ]
    matrix = circulant(row)
    active: list[int] = []
    for r in range(rounds):
        for j in range(m):
            for k in range(64):
                a = enc.new()
                enc.or_equiv(a, [layers[r][5 * j + i][k] for i in range(5)])
                active.append(a)
    enc.add(*active)
    for r in range(rounds - 1):
        sbox = [[enc.new() for _ in range(64)] for _ in range(len(row))]
        for j in range(m):
            for k in range(64):
                a = enc.new()
                b = enc.new()
                enc.or_equiv(a, [layers[r][5 * j + i][k] for i in range(5)])
                enc.or_equiv(b, [sbox[5 * j + i][k] for i in range(5)])
                enc.add(-a, b)
                enc.add(a, -b)
        for t in range(len(row)):
            for k in range(64):
                sources = []
                for j, entry in enumerate(matrix[t]):
                    if not entry:
                        continue
                    for shift in (t, t + 21, t + 43):
                        sources.append(sbox[j][(k - shift) % 64])
                enc.equiv_xor(layers[r + 1][t][k], sources)
    card = CardEnc.atmost(active, bound=bound, top_id=enc.top, encoding=EncType.seqcounter)
    enc.cnf.extend(card.clauses)
    enc.top = max(enc.top, card.nv)
    return enc, layers, active


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--width", type=int, choices=(960, 1920), default=960)
    p.add_argument("--rounds", type=int, default=3)
    p.add_argument("--bound", type=int, required=True)
    p.add_argument("--timeout", type=int, default=30)
    args = p.parse_args()
    enc, layers, active = build(M15_ROW if args.width == 960 else M30_ROW, args.rounds, args.bound)
    started = time.time()
    with Glucose3(bootstrap_with=enc.cnf.clauses, use_timer=True) as solver:
        result = solver.solve_limited(expect_interrupt=True)
        elapsed = time.time() - started
        out = {
            "width": args.width,
            "rounds": args.rounds,
            "bound": args.bound,
            "result": bool(result),
            "elapsed_seconds": elapsed,
            "variables": enc.top,
            "clauses": len(enc.cnf.clauses),
        }
        if result:
            model = set(lit for lit in solver.get_model() if lit > 0)
            witness = []
            for layer in layers:
                values = []
                for j in range(len(layer) // 5):
                    word = 0
                    for k in range(64):
                        cell = sum((1 << i) for i in range(5) if layer[5 * j + i][k] in model)
                        word = (word << 1) | cell
                    values.append(f"{word:016x}")
                witness.append(values)
            out["witness"] = witness
            out["active_total"] = sum(a in model for a in active)
        print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
