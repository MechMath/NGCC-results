#!/usr/bin/env python3
"""Exact cell-support differential model for the pinned Duet permutation.

The only S-box property used is its exact DDT row support: for every nonzero
input difference, all 16 nonzero output differences occur.  The model therefore
retains actual 5-bit cell values and exact MS/ML propagation, but omits DDT
weights.  This is sufficient for an independent check of active-S-box floors.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import time

import z3


M15_ROW = [1, 0, 0, 1, 1, 1, 0, 1, 1, 0, 0, 0, 0, 1, 0]
M30_ROW = [
    1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1,
    1, 1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0,
]


def circulant(row: list[int]) -> list[list[int]]:
    n = len(row)
    return [[row[(j - i) % n] for j in range(n)] for i in range(n)]


def cell_nonzero(words: list[z3.BitVecRef], word: int, bit: int) -> z3.BoolRef:
    return z3.Or(*[z3.Extract(bit, bit, words[5 * word + i]) == 1 for i in range(5)])


def sb_support(words: list[z3.BitVecRef]) -> list[z3.BitVecRef]:
    """Choose a DDT-supported S-box output support, retaining all values."""
    m = len(words) // 5
    out: list[z3.BitVecRef] = []
    for j in range(m):
        for i in range(5):
            out.append(z3.BitVec(f"sb_{j}_{i}", 64))
    for j in range(m):
        for bit in range(64):
            inp_active = cell_nonzero(words, j, bit)
            out_active = cell_nonzero(out, j, bit)
            yield z3.solver().add(inp_active == out_active)
    return out


def sb_support_constraints(words: list[z3.BitVecRef]) -> tuple[list[z3.BitVecRef], list[z3.BoolRef]]:
    m = len(words) // 5
    out = [
        z3.BitVec(f"sb_{j}_{i}", 64)
        for j in range(m)
        for i in range(5)
    ]
    constraints: list[z3.BoolRef] = []
    for j in range(m):
        for bit in range(64):
            constraints.append(cell_nonzero(words, j, bit) == cell_nonzero(out, j, bit))
    return out, constraints


def mix_slice(words: list[z3.BitVecRef], row: list[int]) -> list[z3.BitVecRef]:
    matrix = circulant(row)
    out: list[z3.BitVecRef] = []
    for i, line in enumerate(matrix):
        terms = [words[j] for j, entry in enumerate(line) if entry]
        out.extend([])
        # This is one word slot; the caller handles the 64-bit identity blocks.
        value = terms[0]
        for term in terms[1:]:
            value = value ^ term
        out.append(value)
    return out


def mix_slice_words(words: list[z3.BitVecRef], row: list[int]) -> list[z3.BitVecRef]:
    matrix = circulant(row)
    out = []
    for line in matrix:
        terms = [words[j] for j, entry in enumerate(line) if entry]
        value = terms[0]
        for term in terms[1:]:
            value = value ^ term
        out.append(value)
    return out


def mix_lane(words: list[z3.BitVecRef]) -> list[z3.BitVecRef]:
    return [
        z3.RotateLeft(word, t)
        ^ z3.RotateLeft(word, (t + 21) % 64)
        ^ z3.RotateLeft(word, (t + 43) % 64)
        for t, word in enumerate(words)
    ]


def build(row: list[int], rounds: int) -> tuple[z3.Solver, list[list[z3.BitVecRef]], list[z3.BoolRef], list[z3.BoolRef]]:
    words_per_layer = len(row)
    layers: list[list[z3.BitVecRef]] = [
        [z3.BitVec(f"x_{r}_{i}", 64) for i in range(words_per_layer)]
        for r in range(rounds)
    ]
    solver = z3.Solver()
    active: list[z3.BoolRef] = []
    for r in range(rounds):
        for j in range(words_per_layer // 5):
            for bit in range(64):
                active.append(cell_nonzero(layers[r], j, bit))
    # A differential trail must be nonzero.
    solver.add(z3.Or(*[word != 0 for word in layers[0]]))
    for r in range(rounds - 1):
        out, constraints = sb_support_constraints(layers[r])
        solver.add(*constraints)
        mixed = mix_slice_words(out, row)
        solver.add(*[
            layers[r + 1][i] == value
            for i, value in enumerate(mix_lane(mixed))
        ])
    return solver, layers, active, []


def model_witness(model: z3.ModelRef, layers: list[list[z3.BitVecRef]]) -> dict:
    values = [
        [model.eval(word, model_completion=True).as_long() for word in layer]
        for layer in layers
    ]
    counts = []
    for layer in values:
        counts.append(sum(
            any((layer[5 * j + i] >> bit) & 1 for i in range(5))
            for j in range(len(layer) // 5)
            for bit in range(64)
        ))
    return {"layer_active_sboxes": counts, "state_words_hex": [
        [f"{word:016x}" for word in layer] for layer in values
    ]}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--width", type=int, choices=(960, 1920), default=960)
    parser.add_argument("--rounds", type=int, default=3)
    parser.add_argument("--bound", type=int)
    parser.add_argument("--timeout-ms", type=int, default=120000)
    args = parser.parse_args()
    row = M15_ROW if args.width == 960 else M30_ROW
    solver, layers, active, _ = build(row, args.rounds)
    solver.set(timeout=args.timeout_ms)
    objective = z3.Sum([z3.If(cell, 1, 0) for cell in active])
    if args.bound is not None:
        solver.add(objective <= args.bound)
    started = time.time()
    result = solver.check()
    elapsed = time.time() - started
    record = {
        "width": args.width,
        "rounds": args.rounds,
        "bound": args.bound,
        "result": str(result),
        "elapsed_seconds": elapsed,
        "solver_statistics": solver.statistics(),
        "model_sha256": hashlib.sha256(open(__file__, "rb").read()).hexdigest(),
    }
    if result == z3.sat:
        witness = model_witness(solver.model(), layers)
        record["witness"] = witness
        record["active_total"] = sum(witness["layer_active_sboxes"])
    print(json.dumps(record, indent=2, default=str))


if __name__ == "__main__":
    main()
