#!/usr/bin/env python3
"""XOR/AND q=3 search with symbolic linear expressions between chi layers."""

from __future__ import annotations

import argparse
import time

import pycryptosat

from zc_model import ROUND_CONSTANTS, ZC


class Expr:
    __slots__ = ("variables", "constant")

    def __init__(self, variables: frozenset[int] = frozenset(), constant: bool = False):
        self.variables = variables
        self.constant = constant

    def __xor__(self, other: "Expr") -> "Expr":
        return Expr(self.variables ^ other.variables, self.constant ^ other.constant)


def variable(value: int) -> Expr:
    return Expr(frozenset((value,)), False)


ZERO = Expr()


class Circuit:
    def __init__(self, threads: int = 1) -> None:
        self.solver = pycryptosat.Solver(verbose=1, threads=threads)
        self.next_var = 1
        self.zero = self.new_var()
        self.solver.add_clause([-self.zero])

    def new_var(self) -> int:
        value = self.next_var
        self.next_var += 1
        return value

    def materialize(self, expr: Expr) -> int:
        out = self.new_var()
        self.solver.add_xor_clause(list(expr.variables) + [out], expr.constant)
        return out

    def and_not(self, a: int, b: int) -> int:
        out = self.new_var()
        self.solver.add_clause([-out, a])
        self.solver.add_clause([-out, -b])
        self.solver.add_clause([out, -a, b])
        return out

    def clause(self, literals: list[int]) -> None:
        self.solver.add_clause(literals)


State = list[list[Expr]]


def round_symbolic(circuit: Circuit, zc: ZC, state: State, constant: int) -> State:
    state = [lane[:] for lane in state]
    state[0][0] = state[0][0] ^ Expr(frozenset(), constant != 0)

    old_atoms = [[circuit.materialize(bit) for bit in lane] for lane in state]
    nonlinear: State = [[ZERO] * 64 for _ in range(zc.x_dim * zc.y_dim)]
    for y in range(zc.y_dim):
        y1 = (y + 1) % zc.y_dim
        y2 = (y + 2) % zc.y_dim
        for x in range(zc.x_dim):
            lane = []
            for z in range(64):
                product = circuit.and_not(
                    old_atoms[x * zc.y_dim + y1][z],
                    old_atoms[x * zc.y_dim + y2][z],
                )
                lane.append(state[x * zc.y_dim + y][z] ^ variable(product))
            nonlinear[x * zc.y_dim + y] = lane

    shifted: State = [[ZERO] * 64 for _ in range(zc.x_dim * zc.y_dim)]
    for y in range(zc.y_dim):
        x_rot, z_rot = zc.rho_rotations[y]
        for x in range(zc.x_dim):
            x_src = (x - x_rot) % zc.x_dim
            shifted[x * zc.y_dim + y] = [
                nonlinear[x_src * zc.y_dim + y][(z - z_rot) % 64]
                for z in range(64)
            ]

    parity: list[list[Expr]] = []
    for x in range(zc.x_dim):
        lane = []
        for z in range(64):
            value = ZERO
            for y in range(zc.y_dim):
                value = value ^ shifted[x * zc.y_dim + y][z]
            lane.append(value)
        parity.append(lane)

    a_rot, b_rot = zc.theta_rotations
    effect = []
    for x in range(zc.x_dim):
        source = parity[(x - 1) % zc.x_dim]
        effect.append(
            [
                source[(z - a_rot) % 64] ^ source[(z - b_rot) % 64]
                for z in range(64)
            ]
        )
    mixed: State = [[ZERO] * 64 for _ in range(zc.x_dim * zc.y_dim)]
    for x in range(zc.x_dim):
        for y in range(zc.y_dim):
            mixed[x * zc.y_dim + y] = [
                shifted[x * zc.y_dim + y][z] ^ effect[x][z]
                for z in range(64)
            ]

    final: State = [[ZERO] * 64 for _ in range(zc.x_dim * zc.y_dim)]
    for y in range(zc.y_dim):
        x_rot, z_rot = zc.rho_rotations[y]
        for x in range(zc.x_dim):
            x_src = (x - x_rot) % zc.x_dim
            final[x * zc.y_dim + y] = [
                mixed[x_src * zc.y_dim + y][(z - z_rot) % 64]
                for z in range(64)
            ]
    return final


def permute(circuit: Circuit, zc: ZC, state: State) -> State:
    for constant in ROUND_CONSTANTS:
        state = round_symbolic(circuit, zc, state, constant)
    return state


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--variant", choices=["1280", "1536"], required=True)
    parser.add_argument("--capacity", type=int, required=True)
    parser.add_argument("--threads", type=int, default=1)
    parser.add_argument("--points", type=int, choices=[2, 3], default=3)
    parser.add_argument(
        "--output-bits",
        type=int,
        default=0,
        help="constrain only this leading prefix; 0 means all m bits",
    )
    parser.add_argument(
        "--message-length",
        type=int,
        default=-1,
        help="optionally restrict rate bits to one-block padding of this length",
    )
    args = parser.parse_args()

    zc = ZC.zc1280() if args.variant == "1280" else ZC.zc1536()
    r = zc.m - args.capacity
    circuit = Circuit(args.threads)
    base = [variable(circuit.new_var()) for _ in range(r)]
    d1 = [variable(circuit.new_var()) for _ in range(r)]

    def state_from(bits: list[Expr]) -> State:
        bits = bits + [ZERO] * args.capacity
        return [
            bits[x * 64 : (x + 1) * 64]
            for x in range(zc.x_dim * zc.y_dim)
        ]

    points = [
        state_from(base),
        state_from([a ^ b for a, b in zip(base, d1)]),
    ]
    circuit.clause([next(iter(bit.variables)) for bit in d1])
    if args.message_length >= 0:
        length = args.message_length
        j = (-(length + 4)) % r
        if length + 4 + j != r:
            raise ValueError("message length does not induce exactly one block")
        suffix = "01" + "1" + "0" * j + "1"
        deltas = [d1]
        if args.points == 3:
            d2 = [variable(circuit.new_var()) for _ in range(r)]
            deltas.append(d2)
        else:
            d2 = None
        for offset, char in enumerate(suffix, start=length):
            base_var = next(iter(base[offset].variables))
            circuit.solver.add_clause([base_var if char == "1" else -base_var])
            for delta in deltas:
                delta_var = next(iter(delta[offset].variables))
                circuit.solver.add_clause([-delta_var])
    if args.points == 3:
        if d2 is None:
            raise AssertionError("third-point variables missing")
        points.append(state_from([a ^ b for a, b in zip(base, d2)]))
        circuit.clause([next(iter(bit.variables)) for bit in d2])
        differences = []
        for a, b in zip(d1, d2):
            out = circuit.new_var()
            circuit.solver.add_xor_clause(
                [out] + list(a.variables) + list(b.variables), False
            )
            differences.append(out)
        circuit.clause(differences)

    outputs = [permute(circuit, zc, point) for point in points]
    output_bits = args.output_bits or zc.m
    if not 0 < output_bits <= zc.m:
        raise ValueError("output bits out of range")
    for index in range(output_bits):
        combined = ZERO
        for output in outputs:
            combined = combined ^ output[index // 64][index % 64]
        circuit.solver.add_xor_clause(
            list(combined.variables), combined.constant
        )

    print(
        f"m={zc.m} c={args.capacity} r={r} points={len(points)} "
        f"output_bits={output_bits} "
        f"vars={circuit.next_var - 1}",
        flush=True,
    )
    start = time.monotonic()
    satisfiable, model = circuit.solver.solve()
    print(f"result={satisfiable} elapsed={time.monotonic() - start:.3f}s", flush=True)
    if not satisfiable:
        return

    def expr_value(expr: Expr) -> int:
        return int(expr.constant) ^ sum(bool(model[var]) for var in expr.variables) % 2

    values = []
    for point in points:
        bits = [expr_value(bit) for lane in point for bit in lane]
        value = sum(bit << i for i, bit in enumerate(bits))
        values.append(value)
    replay = 0
    for value in values:
        replay ^= zc.permute_int(value)
    width = (zc.m + 3) // 4
    for index, value in enumerate(values):
        print(f"A{index}={value:0{width}x}")
    print(f"replay_xor={replay:0{width}x}")
    mask = (1 << output_bits) - 1
    print(
        f"replay_rate_xor_ok={(replay & mask) == 0} "
        f"distinct={len(set(values)) == len(values)}"
    )


if __name__ == "__main__":
    main()
