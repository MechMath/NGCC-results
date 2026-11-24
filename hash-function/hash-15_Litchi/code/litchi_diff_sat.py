#!/usr/bin/env python3
"""CNF search for a specific Litchi capacity-to-capacity differential.

This is a local research note.  A satisfying assignment is a complete 16-round
differential trail; replay and DDT weight calculation remain mandatory.
"""

from __future__ import annotations

import argparse
from collections import defaultdict
import signal

from pysat.solvers import Solver


SBOX = [
    0, 2, 4, 23, 8, 10, 14, 13, 16, 18, 20, 15, 28, 30, 26, 17,
    1, 19, 5, 6, 9, 27, 31, 12, 25, 11, 29, 22, 21, 7, 3, 24,
]
THETAS = [
    (31, 1, 4, 21, 22),
    (19, 12, 15, 34, 13),
    (28, 35, 58, 9, 23),
    (55, 18, 5, 27, 44),
    (14, 43, 53, 20, 25),
]


class CNF:
    def __init__(self) -> None:
        self.n = 0
        self.clauses: list[list[int]] = []

    def var(self) -> int:
        self.n += 1
        return self.n

    def add(self, clause: list[int]) -> None:
        self.clauses.append(clause)

    def xor2(self, a: int, b: int) -> int:
        out = self.var()
        self.add([-out, a, b])
        self.add([-out, -a, -b])
        self.add([out, -a, b])
        self.add([out, a, -b])
        return out

    def xor_many(self, values: list[int]) -> int:
        current = values[0]
        for value in values[1:]:
            current = self.xor2(current, value)
        return current


def allowed_pairs() -> set[tuple[int, int]]:
    pairs = set()
    for alpha in range(32):
        for beta in range(32):
            if any((SBOX[x] ^ SBOX[x ^ alpha]) == beta for x in range(32)):
                pairs.add((alpha, beta))
    return pairs


def flatten(state: list[list[list[int]]]) -> list[list[list[int]]]:
    """Return [plane][lane][k], with k=0 the most significant bit."""
    return state


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rounds", type=int, default=16)
    parser.add_argument("--capacity", type=int, default=576)
    parser.add_argument("--timeout", type=int, default=300)
    parser.add_argument("--min-ddt", type=int, default=2, choices=(2, 4, 8))
    args = parser.parse_args()

    cnf = CNF()
    state = [
        [[cnf.var() for _ in range(64)] for _ in range(5)]
        for _ in range(5)
    ]

    def cap_bits(state: list[list[list[int]]]) -> list[int]:
        return [
            state[p][l][k]
            for p in range(5)
            for l in range(5)
            for k in range(64)
        ][-args.capacity:]

    def rate_bits(state: list[list[list[int]]]) -> list[int]:
        return [
            state[p][l][k]
            for p in range(5)
            for l in range(5)
            for k in range(64)
        ][:-args.capacity]

    for bit in cap_bits(state):
        cnf.add([-bit])
    cnf.add(rate_bits(state))

    allowed = {
        (alpha, beta)
        for alpha, beta in allowed_pairs()
        if alpha == 0
        or sum((SBOX[x] ^ SBOX[x ^ alpha]) == beta for x in range(32)) >= args.min_ddt
    }
    forbidden = [(a, b) for a in range(32) for b in range(32) if (a, b) not in allowed]
    round_data = []

    for rnd in range(args.rounds):
        input_state = state
        # chi: one transition relation per (lane, bit-position) column.
        chi = [[[None for _ in range(64)] for _ in range(5)] for _ in range(5)]
        for lane in range(5):
            for k in range(64):
                ins = [state[p][lane][k] for p in range(5)]
                outs = [cnf.var() for _ in range(5)]
                for p in range(5):
                    chi[p][lane][k] = outs[p]
                # Block every unsupported five-bit input/output assignment.
                for alpha, beta in forbidden:
                    clause = []
                    for p in range(5):
                        # literal is false when the chosen bit matches alpha/beta
                        clause.append(-ins[p] if ((alpha >> (4 - p)) & 1) else ins[p])
                    for p in range(5):
                        clause.append(-outs[p] if ((beta >> (4 - p)) & 1) else outs[p])
                    cnf.add(clause)
        round_data.append((input_state, chi))

        # theta: exact XOR masks, with bit-position rotations.
        theta = [[[None for _ in range(64)] for _ in range(5)] for _ in range(5)]
        for p, shifts in enumerate(THETAS):
            for k in range(64):
                e_terms = [chi[p][lane][k] for lane in range(5)]
                e_at = {
                    q: cnf.xor_many([chi[p][lane][(q - shifts[lane]) % 64]
                                     for lane in range(5)])
                    for q in {(k + shifts[lane]) % 64 for lane in range(5)}
                }
                f = cnf.xor_many([chi[p][lane][(k - shifts[lane]) % 64]
                                  for lane in range(5)])
                for lane, shift in enumerate(shifts):
                    theta[p][lane][k] = cnf.xor_many(
                        [chi[p][lane][k], e_at[(k + shift) % 64], f]
                    )

        # pi: B[i][j] = A[(i+2j)%5][(3i+3j)%5].
        state = [[[None for _ in range(64)] for _ in range(5)] for _ in range(5)]
        for i in range(5):
            for j in range(5):
                for k in range(64):
                    state[i][j][k] = theta[(i + 2 * j) % 5][(3 * i + 3 * j) % 5][k]
        print("round", rnd + 1, "vars", cnf.n, "clauses", len(cnf.clauses), flush=True)

    for bit in cap_bits(state):
        cnf.add([-bit])

    print("final vars", cnf.n, "clauses", len(cnf.clauses), flush=True)
    with Solver(bootstrap_with=cnf.clauses, name="cadical195") as solver:
        def timed_out(_signum, _frame):
            raise TimeoutError

        previous = signal.signal(signal.SIGALRM, timed_out)
        signal.alarm(args.timeout)
        try:
            ok = solver.solve()
        except TimeoutError:
            ok = None
        finally:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, previous)
        print("result", ok, "stats", solver.accum_stats(), flush=True)
        if not ok:
            return
        model = set(lit for lit in solver.get_model() if lit > 0)

    def word(p: int, lane: int) -> int:
        value = 0
        for k in range(64):
            value = (value << 1) | int(state[p][lane][k] in model)
        return value

    print("output_words_hex")
    for p in range(5):
        print(" ".join(f"{word(p, lane):016x}" for lane in range(5)))

    def five_bits(bits: list[int], lane: int, k: int) -> int:
        value = 0
        for p in range(5):
            value = (value << 1) | int(bits[p][lane][k] in model)
        return value

    total_active = 0
    total_weight = 0
    for rnd, (before, after) in enumerate(round_data, 1):
        active = 0
        weight = 0
        for lane in range(5):
            for k in range(64):
                alpha = five_bits(before, lane, k)
                beta = five_bits(after, lane, k)
                if alpha == 0:
                    continue
                active += 1
                count = sum((SBOX[x] ^ SBOX[x ^ alpha]) == beta for x in range(32))
                if count == 0:
                    raise AssertionError((rnd, lane, k, alpha, beta))
                weight += 5 - count.bit_length() + 1
        total_active += active
        total_weight += weight
        print("round_stats", rnd, "active", active, "differential_weight", weight)
    print("total_stats", "active", total_active, "differential_weight", total_weight)


if __name__ == "__main__":
    main()
