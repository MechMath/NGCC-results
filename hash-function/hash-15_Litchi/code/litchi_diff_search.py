#!/usr/bin/env python3
"""Quick exact Z3 search for Litchi capacity-constrained differential trails.

This file is a local research note, not execution evidence.  It models the
specification's differential through chi exactly using its five ANF coordinates,
then applies the specified theta and pi layers.  A returned model must still be
replayed and its differential weight computed from the DDT.
"""

from __future__ import annotations

import argparse

import z3


THETAS = [
    (31, 1, 4, 21, 22),
    (19, 12, 15, 34, 13),
    (28, 35, 58, 9, 23),
    (55, 18, 5, 27, 44),
    (14, 43, 53, 20, 25),
]


def sbox_expr(x: list[z3.BitVecRef]) -> list[z3.BitVecRef]:
    a0, a1, a2, a3, a4 = x
    return [
        (a0 & a2 & a3)
        ^ (a2 & a3 & a4)
        ^ (a0 & a4)
        ^ (a3 & a4)
        ^ a1,
        (a1 & a3 & a4) ^ (a0 & a1) ^ a2,
        (a1 & a2) ^ a3,
        (a2 & a3) ^ a4,
        (a3 & a4) ^ a0,
    ]


def chi_diff(state: list[list[z3.BitVecRef]]) -> list[list[z3.BitVecRef]]:
    out = [[None for _ in range(5)] for _ in range(5)]
    for lane in range(5):
        a = [state[plane][lane] for plane in range(5)]
        b = sbox_expr(a)
        # The translation by the round constant does not affect a difference.
        for plane in range(5):
            out[plane][lane] = b[plane]
    return out


def theta_diff(state: list[list[z3.BitVecRef]]) -> list[list[z3.BitVecRef]]:
    out = [[None for _ in range(5)] for _ in range(5)]
    for plane, ts in enumerate(THETAS):
        words = state[plane]
        e = words[0]
        for word in words[1:]:
            e = e ^ word
        f = z3.RotateLeft(words[0], ts[0])
        for word, shift in zip(words[1:], ts[1:]):
            f = f ^ z3.RotateLeft(word, shift)
        for lane, shift in enumerate(ts):
            out[plane][lane] = words[lane] ^ z3.RotateRight(e, shift) ^ f
    return out


def pi(state: list[list[z3.BitVecRef]]) -> list[list[z3.BitVecRef]]:
    out = [[None for _ in range(5)] for _ in range(5)]
    for i in range(5):
        for j in range(5):
            # B[i][j] = A[(i+2j) mod 5][(3i+3j) mod 5]
            out[i][j] = state[(i + 2 * j) % 5][(3 * i + 3 * j) % 5]
    return out


def one_round(state: list[list[z3.BitVecRef]]) -> list[list[z3.BitVecRef]]:
    return pi(theta_diff(chi_diff(state)))


def bits_msb_first(state: list[list[z3.BitVecRef]]) -> list[z3.BitVecRef]:
    bits = []
    for plane in range(5):
        for lane in range(5):
            bits.extend(z3.Extract(63 - k, 63 - k, state[plane][lane]) for k in range(64))
    return bits


def nonzero_bits(bits: list[z3.BitVecRef]) -> z3.BoolRef:
    return z3.Or(*[bit == 1 for bit in bits])


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rounds", type=int, default=16)
    parser.add_argument("--capacity", type=int, default=576)
    parser.add_argument("--timeout-ms", type=int, default=30000)
    parser.add_argument("--seed", type=int, default=1)
    args = parser.parse_args()

    state = [[z3.BitVec(f"in_{i}_{j}", 64) for j in range(5)] for i in range(5)]
    in_bits = bits_msb_first(state)
    rate = in_bits[:-args.capacity]
    solver = z3.Then("simplify", "bit-blast", "sat").solver()
    solver.set(timeout=args.timeout_ms, random_seed=args.seed)
    solver.add(*(bit == 0 for bit in in_bits[-args.capacity:]))
    solver.add(nonzero_bits(rate))

    current = state
    for _ in range(args.rounds):
        current = one_round(current)
    out_bits = bits_msb_first(current)
    solver.add(*(bit == 0 for bit in out_bits[-args.capacity:]))

    result = solver.check()
    print("rounds", args.rounds, "capacity", args.capacity, "result", result)
    if result != z3.sat:
        if result == z3.unknown:
            print(solver.reason_unknown())
        return

    model = solver.model()
    mask = (1 << 64) - 1

    def lane_value(i: int, j: int) -> int:
        return model.eval(state[i][j], model_completion=True).as_long() & mask

    in_words = [[lane_value(i, j) for j in range(5)] for i in range(5)]
    print("input_words_hex")
    for row in in_words:
        print(" ".join(f"{word:016x}" for word in row))


if __name__ == "__main__":
    main()
