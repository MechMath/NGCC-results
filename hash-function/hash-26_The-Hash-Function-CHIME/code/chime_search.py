#!/usr/bin/env python3
"""Searches over CHIME's exact repeated-64-bit-word invariant subspace."""

from __future__ import annotations

from dataclasses import dataclass
import argparse
import time

import z3

import chime_ref as ref


MASK64 = ref.MASK64


def expand(words: list[int]) -> list[int]:
    return [ref.repeat_word(x) for x in words]


def contract(state: list[int]) -> list[int]:
    words = [(x >> 192) & MASK64 for x in state]
    assert all(x == ref.repeat_word(w) for x, w in zip(state, words))
    return words


def round_word(words: list[int], rnd: int) -> list[int]:
    return contract(ref.round_function(expand(words), rnd))


def permutation_words(words: list[int], rounds: int) -> list[int]:
    for rnd in range(rounds):
        words = round_word(words, rnd)
    return words


def zrol(x, n: int):
    return (x << n) | z3.LShR(x, 64 - n)


def zror(x, n: int):
    return (x >> n) | (x << (64 - n))


def zlinear(s):
    a0, a1, b0, b1, c0, c1 = s
    b1 = b1 ^ c1
    b0 = b0 ^ a1
    c0 = c0 ^ zrol(a0, 29)
    b1 = b1 ^ zrol(a1, 31)
    c1 = c1 ^ zrol(a0, 13)
    c0 = c0 ^ b1
    c1 = c1 ^ b1
    a0 = a0 ^ c0
    a1 = a1 ^ b0
    b1 = b1 ^ zrol(a0, 7)
    c1 = c1 ^ zror(a1, 5)
    return [a0, a1, b0, b1, c0, c1]


def zchi(s, rnd: int):
    a0, a1, b0, b1, c0, c1 = s
    if rnd % 2 == 0:
        x0, x1, x2, names = a0, b0, c0, (0, 2, 4)
        u0, u1, u2, names1 = a1, b1, c1, (1, 3, 5)
    else:
        x0, x1, x2, names = a0, b1, c1, (0, 3, 5)
        u0, u1, u2, names1 = a1, b0, c0, (1, 2, 4)
    out = [None] * 6
    out[names[0]] = x0 ^ (~x1 & x2)
    out[names[1]] = x1 ^ (~x2 & x0)
    out[names[2]] = x2 ^ (~x0 & x1)
    out[names1[0]] = u0 ^ (~u1 & u2)
    out[names1[1]] = u1 ^ (~u2 & u0)
    out[names1[2]] = u2 ^ (~u0 & u1)
    return out


def ztau(s, rnd: int):
    a0, a1, b0, b1, c0, c1 = s
    if (rnd // 3) % 2 == 0:
        return [c1, a0, a1, b0, b1, c0]
    return [a1, b0, b1, c0, c1, a0]


def zround(s, rnd: int):
    s = zlinear(s)
    s[0] = s[0] ^ z3.BitVecVal(ref.round_constant(rnd), 64)
    return ztau(zchi(s, rnd), rnd)


def solve_fixed_point(rounds: int, timeout_ms: int) -> tuple[str, list[int] | None]:
    s = [z3.BitVec(f"s{i}", 64) for i in range(6)]
    out = s
    for rnd in range(rounds):
        out = zround(out, rnd)
    solver = z3.Solver()
    solver.set(timeout=timeout_ms)
    for i in range(6):
        solver.add(out[i] == s[i])
    result = solver.check()
    if result == z3.sat:
        model = solver.model()
        return "sat", [model.eval(x).as_long() for x in s]
    return str(result), None


def solve_512_invariant_collision(blocks: int, timeout_ms: int):
    """Find two distinct CHIME-512 messages whose padded blocks are 4-repeat."""
    messages = []
    states = []
    for _ in range(2):
        words = [z3.BitVec(f"m_{len(messages)}_{i}", 64) for i in range(blocks)]
        state = [z3.BitVecVal(0, 64) for _ in range(6)]
        for rnd in range(blocks):
            state = [state[j] ^ (words[rnd] if j < 2 else z3.BitVecVal(0, 64))
                     for j in range(6)]
            for round_index in range(15):
                state = zround(state, round_index)
        messages.append(words)
        states.append(state)
    solver = z3.Solver()
    solver.set(timeout=timeout_ms)
    for i in range(2):
        solver.add(states[i][0] == states[1][0])
        solver.add(states[i][1] == states[1][1])
    solver.add(z3.Or(*[messages[0][i] != messages[1][i] for i in range(blocks)]))
    result = solver.check()
    if result == z3.sat:
        model = solver.model()
        witnesses = [[model.eval(x).as_long() for x in words] for words in messages]
        return "sat", witnesses
    return str(result), None


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--fixed-rounds", type=int)
    ap.add_argument("--collision-blocks", type=int)
    ap.add_argument("--timeout-ms", type=int, default=50000)
    args = ap.parse_args()
    if args.fixed_rounds:
        start = time.time()
        result, witness = solve_fixed_point(args.fixed_rounds, args.timeout_ms)
        print("result", result, "seconds", time.time() - start)
        if witness is not None:
            print("witness", [f"{x:016x}" for x in witness])
            print("check", permutation_words(witness, args.fixed_rounds) == witness)
    if args.collision_blocks:
        start = time.time()
        result, witnesses = solve_512_invariant_collision(
            args.collision_blocks, args.timeout_ms)
        print("collision result", result, "seconds", time.time() - start)
        if witnesses is not None:
            print("witness words", [[f"{x:016x}" for x in ws] for ws in witnesses])


if __name__ == "__main__":
    main()
