#!/usr/bin/env python3
"""Native XOR/AND q=3 solver for capacity-zero ZC zero-sums."""

from __future__ import annotations

import argparse
import time

import pycryptosat

from zc_model import ROUND_CONSTANTS, ZC


Literal = int
Lane = list[Literal]


class Circuit:
    def __init__(self, threads: int = 1, matrix_cols: int = 5000, matrix_rows: int = 3000) -> None:
        self.solver = pycryptosat.Solver(
            verbose=1,
            threads=threads,
            options={
                "maxmatrixcols": str(matrix_cols),
                "maxmatrixrows": str(matrix_rows),
                "autodisablegauss": "0",
            },
        )
        self.next_var = 1

    def new_var(self) -> int:
        var = self.next_var
        self.next_var += 1
        return var

    def unit(self, literal: Literal) -> None:
        self.solver.add_clause([literal])

    def clause(self, literals: list[Literal]) -> None:
        self.solver.add_clause(literals)

    def xor(self, literals: list[Literal], rhs: bool = False) -> int:
        out = self.new_var()
        variables = []
        variable_rhs = rhs
        for literal in literals:
            if literal < 0:
                variable_rhs = not variable_rhs
            variables.append(abs(literal))
        self.solver.add_xor_clause(variables + [out], variable_rhs)
        return out

    def and_not(self, a: Literal, b: Literal) -> int:
        """Return a AND (NOT b)."""
        out = self.new_var()
        self.solver.add_clause([-out, a])
        self.solver.add_clause([-out, -b])
        self.solver.add_clause([out, -a, b])
        return out


def initial_lane(circuit: Circuit, bits: list[Literal]) -> Lane:
    return bits[:]


def add_xor_literal(circuit: Circuit, a: Literal, b: Literal) -> int:
    return circuit.xor([a, b])


def round_lanes(circuit: Circuit, zc: ZC, state: list[Lane], constant: int) -> list[Lane]:
    state = [lane[:] for lane in state]
    for z in range(64):
        if (constant >> z) & 1:
            state[0][z] = -state[0][z]

    old = [lane[:] for lane in state]
    nonlinear: list[Lane] = [[0] * 64 for _ in range(zc.x_dim * zc.y_dim)]
    for y in range(zc.y_dim):
        y1 = (y + 1) % zc.y_dim
        y2 = (y + 2) % zc.y_dim
        for x in range(zc.x_dim):
            lane = []
            for z in range(64):
                product = circuit.and_not(
                    old[x * zc.y_dim + y1][z],
                    old[x * zc.y_dim + y2][z],
                )
                lane.append(
                    circuit.xor([old[x * zc.y_dim + y][z], product])
                )
            nonlinear[x * zc.y_dim + y] = lane

    shifted = [[0] * 64 for _ in range(zc.x_dim * zc.y_dim)]
    for y in range(zc.y_dim):
        x_rot, z_rot = zc.rho_rotations[y]
        for x in range(zc.x_dim):
            x_src = (x - x_rot) % zc.x_dim
            shifted[x * zc.y_dim + y] = [
                nonlinear[x_src * zc.y_dim + y][(z - z_rot) % 64]
                for z in range(64)
            ]

    parity: list[Lane] = []
    for x in range(zc.x_dim):
        lane = []
        for z in range(64):
            lane.append(
                circuit.xor(
                    [shifted[x * zc.y_dim + y][z] for y in range(zc.y_dim)]
                )
            )
        parity.append(lane)

    a_rot, b_rot = zc.theta_rotations
    effect: list[Lane] = []
    for x in range(zc.x_dim):
        source = parity[(x - 1) % zc.x_dim]
        effect.append(
            [
                circuit.xor(
                    [
                        source[(z - a_rot) % 64],
                        source[(z - b_rot) % 64],
                    ]
                )
                for z in range(64)
            ]
        )
    mixed = [
        [
            circuit.xor([shifted[x * zc.y_dim + y][z], effect[x][z]])
            for z in range(64)
        ]
        for x in range(zc.x_dim)
        for y in range(zc.y_dim)
    ]

    final = [[0] * 64 for _ in range(zc.x_dim * zc.y_dim)]
    for y in range(zc.y_dim):
        x_rot, z_rot = zc.rho_rotations[y]
        for x in range(zc.x_dim):
            x_src = (x - x_rot) % zc.x_dim
            final[x * zc.y_dim + y] = [
                mixed[x_src * zc.y_dim + y][(z - z_rot) % 64]
                for z in range(64)
            ]
    return final


def permute(circuit: Circuit, zc: ZC, state: list[Lane]) -> list[Lane]:
    for constant in ROUND_CONSTANTS:
        state = round_lanes(circuit, zc, state, constant)
    return state


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--variant", choices=["1280", "1536"], default="1280")
    parser.add_argument("--capacity", type=int, default=576)
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--threads", type=int, default=1)
    parser.add_argument("--matrix-cols", type=int, default=5000)
    parser.add_argument("--matrix-rows", type=int, default=3000)
    args = parser.parse_args()

    zc = ZC.zc1280() if args.variant == "1280" else ZC.zc1536()
    r = zc.m - args.capacity
    circuit = Circuit(
        threads=args.threads,
        matrix_cols=args.matrix_cols,
        matrix_rows=args.matrix_rows,
    )

    base = [circuit.new_var() for _ in range(r)]
    d1 = [circuit.new_var() for _ in range(r)]
    d2 = [circuit.new_var() for _ in range(r)]
    zero = circuit.new_var()
    circuit.unit(-zero)

    points = []
    for delta in [None, d1, d2]:
        bits = base[:] if delta is None else [
            add_xor_literal(circuit, a, b) for a, b in zip(base, delta)
        ]
        bits += [zero] * args.capacity
        points.append([bits[x * 64 : (x + 1) * 64] for x in range(zc.x_dim * zc.y_dim)])

    circuit.clause(d1)
    circuit.clause(d2)
    differences = [add_xor_literal(circuit, a, b) for a, b in zip(d1, d2)]
    circuit.clause(differences)

    outputs = [permute(circuit, zc, point) for point in points]
    for index in range(zc.m):
        output_bits = [
            outputs[q][index // 64][index % 64] for q in range(3)
        ]
        if any(not isinstance(bit, int) or bit == 0 for bit in output_bits):
            raise AssertionError(
                f"bad output literal at {index}: "
                f"{output_bits}"
            )
        circuit.solver.add_xor_clause(
            output_bits,
            False,
        )

    print(
        f"m={zc.m} c={args.capacity} r={r} vars={circuit.next_var - 1} "
        f"seed={args.seed} threads={args.threads}",
        flush=True,
    )
    start = time.monotonic()
    satisfiable, model = circuit.solver.solve()
    elapsed = time.monotonic() - start
    print(f"result={satisfiable} elapsed={elapsed:.3f}s", flush=True)
    if not satisfiable:
        return

    def get(bits: list[int]) -> int:
        value = 0
        for index, bit in enumerate(bits):
            if model[bit]:
                value |= 1 << index
        return value

    values = []
    for index, point in enumerate(points):
        flat = [lit if lit > 0 else 0 for lane in point for lit in lane]
        values.append(get(flat))
    total = 0
    for value in values:
        total ^= zc.permute_int(value)
    print(f"A0={values[0]:0{(zc.m + 3) // 4}x}")
    print(f"A1={values[1]:0{(zc.m + 3) // 4}x}")
    print(f"A2={values[2]:0{(zc.m + 3) // 4}x}")
    print(f"replay_xor={total:0{(zc.m + 3) // 4}x}")
    print(f"replay_ok={total == 0 and len(set(values)) == 3}")


if __name__ == "__main__":
    main()
