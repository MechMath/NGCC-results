#!/usr/bin/env python3
"""Z3 q=3 search for distinct H points whose P-images XOR to zero."""

from __future__ import annotations

import argparse
import time

import z3

from zc_model import ROUND_CONSTANTS, ZC


def bv64(value: int) -> z3.BitVecRef:
    return z3.BitVecVal(value, 64)


def symbolic_round(
    zc: ZC,
    state: list[list[z3.BitVecRef]],
    constant: int,
) -> list[list[z3.BitVecRef]]:
    out = [row[:] for row in state]
    out[0][0] = out[0][0] ^ bv64(constant)

    old = out
    out = [[old[y][x] for x in range(zc.x_dim)] for y in range(zc.y_dim)]
    for y in range(zc.y_dim):
        y1 = (y + 1) % zc.y_dim
        y2 = (y + 2) % zc.y_dim
        for x in range(zc.x_dim):
            out[y][x] = old[y][x] ^ ((~old[y1][x]) & old[y2][x])

    shifted = [[None] * zc.x_dim for _ in range(zc.y_dim)]
    for y in range(zc.y_dim):
        x_rot, z_rot = zc.rho_rotations[y]
        for x in range(zc.x_dim):
            x_src = (x - x_rot) % zc.x_dim
            shifted[y][x] = z3.RotateLeft(out[y][x_src], z_rot)

    parity = []
    for x in range(zc.x_dim):
        p = shifted[0][x]
        for y in range(1, zc.y_dim):
            p = p ^ shifted[y][x]
        parity.append(p)
    a_rot, b_rot = zc.theta_rotations
    effect = [
        z3.RotateLeft(parity[(x - 1) % zc.x_dim], a_rot)
        ^ z3.RotateLeft(parity[(x - 1) % zc.x_dim], b_rot)
        for x in range(zc.x_dim)
    ]
    mixed = [
        [shifted[y][x] ^ effect[x] for x in range(zc.x_dim)]
        for y in range(zc.y_dim)
    ]

    final = [[None] * zc.x_dim for _ in range(zc.y_dim)]
    for y in range(zc.y_dim):
        x_rot, z_rot = zc.rho_rotations[y]
        for x in range(zc.x_dim):
            x_src = (x - x_rot) % zc.x_dim
            final[y][x] = z3.RotateLeft(mixed[y][x_src], z_rot)
    return final


def symbolic_permute(
    zc: ZC,
    state: list[list[z3.BitVecRef]],
) -> list[list[z3.BitVecRef]]:
    for constant in ROUND_CONSTANTS:
        state = symbolic_round(zc, state, constant)
    return state


def constrain_H(
    zc: ZC,
    solver: z3.Solver,
    state: list[list[z3.BitVecRef]],
    c: int,
) -> None:
    for bit in range(c):
        x = bit // (64 * zc.y_dim)
        rem = bit % (64 * zc.y_dim)
        y, z = divmod(rem, 64)
        solver.add(z3.Extract(z, z, state[y][x]) == 0)


def state_var(zc: ZC, name: str) -> list[list[z3.BitVecRef]]:
    return [
        [z3.BitVec(f"{name}_{x}_{y}", 64) for x in range(zc.x_dim)]
        for y in range(zc.y_dim)
    ]


def xor_state(
    a: list[list[z3.BitVecRef]],
    b: list[list[z3.BitVecRef]],
) -> list[list[z3.BitVecRef]]:
    return [[a[y][x] ^ b[y][x] for x in range(len(a[0]))] for y in range(len(a))]


def state_nonzero(
    solver: z3.Solver,
    state: list[list[z3.BitVecRef]],
) -> None:
    solver.add(z3.Or(*[lane != 0 for row in state for lane in row]))


def states_distinct(
    solver: z3.Solver,
    a: list[list[z3.BitVecRef]],
    b: list[list[z3.BitVecRef]],
) -> None:
    solver.add(z3.Or(*[a[y][x] != b[y][x] for y in range(len(a)) for x in range(len(a[0]))]))


def state_value(model: z3.ModelRef, state: list[list[z3.BitVecRef]], zc: ZC) -> int:
    flat = [model.eval(state[y][x], model_completion=True).as_long() for y in range(zc.y_dim) for x in range(zc.x_dim)]
    return zc.int_from_state(
        [[flat[y * zc.x_dim + x] for x in range(zc.x_dim)] for y in range(zc.y_dim)]
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--variant", choices=["1280", "1536"], default="1280")
    parser.add_argument("--capacity", type=int, default=576)
    parser.add_argument("--timeout-ms", type=int, default=900_000)
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--output-bits", type=int, default=0)
    args = parser.parse_args()

    zc = ZC.zc1280() if args.variant == "1280" else ZC.zc1536()
    r = zc.m - args.capacity
    solver = z3.Solver()
    solver.set(timeout=args.timeout_ms, random_seed=args.seed)

    base = state_var(zc, "base")
    d1 = state_var(zc, "d1")
    d2 = state_var(zc, "d2")
    points = [base, xor_state(base, d1), xor_state(base, d2)]

    for point in points:
        constrain_H(zc, solver, point, args.capacity)
    state_nonzero(solver, d1)
    state_nonzero(solver, d2)
    states_distinct(solver, d1, d2)

    outputs = [symbolic_permute(zc, point) for point in points]
    output_bits = args.output_bits or zc.m
    for index in range(output_bits):
        x = index // (64 * zc.y_dim)
        rem = index % (64 * zc.y_dim)
        y, z = divmod(rem, 64)
        solver.add(
            z3.Extract(z, z, outputs[0][y][x])
            ^ z3.Extract(z, z, outputs[1][y][x])
            ^ z3.Extract(z, z, outputs[2][y][x])
            == 0
        )

    start = time.monotonic()
    result = solver.check()
    elapsed = time.monotonic() - start
    print(f"m={zc.m} c={args.capacity} r={r} seed={args.seed}")
    print(f"result={result} elapsed={elapsed:.3f}s")
    if result != z3.sat:
        return
    model = solver.model()
    values = [state_value(model, point, zc) for point in points]
    for index, value in enumerate(values):
        print(f"A{index}={value:0{(zc.m + 3) // 4}x}")
    total = 0
    for value in values:
        total ^= zc.permute_int(value)
    print(f"replay_xor={total:0{(zc.m + 3) // 4}x}")
    mask = (1 << output_bits) - 1
    print(
        f"replay_rate_xor_ok={(total & mask) == 0} "
        f"distinct={len(set(values)) == 3}"
    )


if __name__ == "__main__":
    main()
