#!/usr/bin/env python3
"""Exact ROBDD probe for a 64-dimensional ZC-1536 lane cube.

This is exploratory native code, not execution evidence.  The cube varies the
64 z-bits of plane 0, lane 0 and fixes every other input bit to zero.
"""

from __future__ import annotations

import argparse
import time

MASK = (1 << 64) - 1
RC = [0x58, 0x38, 0x3C0, 0xD0, 0x60, 0x120,
      0x14, 0x2C, 0xF0, 0x1A0, 0x380, 0x12]
RHO = [(0, 0), (3, 3), (5, 0)]
THETA = (20, 56)


class BDD:
    def __init__(self, variables: int):
        self.variables = variables
        self.var = [-2, -1]
        self.lo = [0, 1]
        self.hi = [0, 1]
        self.unique: dict[tuple[int, int, int], int] = {}
        self.vars = [self.mk(v, 0, 1) for v in range(variables)]
        self.and_cache: dict[tuple[int, int], int] = {}
        self.xor_cache: dict[tuple[int, int], int] = {}

    def mk(self, v: int, lo: int, hi: int) -> int:
        if lo == hi:
            return lo
        key = (v, lo, hi)
        found = self.unique.get(key)
        if found is not None:
            return found
        node = len(self.var)
        self.unique[key] = node
        self.var.append(v)
        self.lo.append(lo)
        self.hi.append(hi)
        return node

    @staticmethod
    def _ordered(a: int, b: int, var: list[int]) -> int:
        return a if var[a] <= var[b] else b

    def xor(self, a: int, b: int) -> int:
        if a == 0:
            return b
        if b == 0:
            return a
        if a == b:
            return 0
        if a > b:
            a, b = b, a
        key = (a, b)
        found = self.xor_cache.get(key)
        if found is not None:
            return found
        va = self.var[a] if a >= 2 else self.variables + 1
        vb = self.var[b] if b >= 2 else self.variables + 1
        v = min(va, vb)
        alo, ahi = (self.lo[a], self.hi[a]) if va == v else (a, a)
        blo, bhi = (self.lo[b], self.hi[b]) if vb == v else (b, b)
        out = self.mk(v, self.xor(alo, blo), self.xor(ahi, bhi))
        self.xor_cache[key] = out
        return out

    def and_(self, a: int, b: int) -> int:
        if a == 0 or b == 0:
            return 0
        if a == 1:
            return b
        if b == 1:
            return a
        if a == b:
            return a
        if a > b:
            a, b = b, a
        key = (a, b)
        found = self.and_cache.get(key)
        if found is not None:
            return found
        va = self.var[a] if a >= 2 else self.variables + 1
        vb = self.var[b] if b >= 2 else self.variables + 1
        v = min(va, vb)
        alo, ahi = (self.lo[a], self.hi[a]) if va == v else (a, a)
        blo, bhi = (self.lo[b], self.hi[b]) if vb == v else (b, b)
        out = self.mk(v, self.and_(alo, blo), self.and_(ahi, bhi))
        self.and_cache[key] = out
        return out

    def not_(self, a: int) -> int:
        return self.xor(a, 1)

    def parity_all(self, u: int, level: int = 0) -> int:
        """XOR of the truth table of u over all 64 assignments."""
        if level == self.variables:
            return u
        if u < 2:
            # At least one remaining free variable: each assignment appears an
            # even number of times.
            return 0
        v = self.var[u]
        if v > level:
            return 0
        return self.parity_all(self.lo[u], v + 1) ^ self.parity_all(self.hi[u], v + 1)


def const_lane(bit: int) -> list[int]:
    return [bit] * 64 if bit else [0] * 64


def rol(v: list[int], n: int) -> list[int]:
    n %= 64
    return v if n == 0 else v[-n:] + v[:-n]


def chi3(b: BDD, x: list[list[list[int]]]) -> list[list[list[int]]]:
    out = [[[0] * 64 for _ in range(8)] for _ in range(3)]
    for lane in range(8):
        for z in range(64):
            for i in range(3):
                y1, y2 = x[(i + 1) % 3][lane], x[(i + 2) % 3][lane]
                out[i][lane][z] = b.xor(
                    x[i][lane][z], b.and_(b.not_(y1[z]), y2[z])
                )
    return out


def inv_chi3(b: BDD, y: list[list[list[int]]]) -> list[list[list[int]]]:
    out = [[[0] * 64 for _ in range(8)] for _ in range(3)]
    for lane in range(8):
        for z in range(64):
            y0v, y1v, y2v = y[0][lane][z], y[1][lane][z], y[2][lane][z]
            out[0][lane][z] = b.xor(b.xor(y0v, y2v), b.and_(y1v, y2v))
            out[1][lane][z] = b.xor(b.xor(y0v, y1v), b.and_(y0v, y2v))
            out[2][lane][z] = b.xor(b.xor(y1v, y2v), b.and_(y0v, y1v))
    return out


def rho(state: list[list[int]], inverse: bool = False) -> list[list[int]]:
    out = []
    for y, (a, dz) in enumerate(RHO):
        if inverse:
            a = -a
            dz = -dz
        out.append([rol(state[y][(x - a) % 8], dz) for x in range(8)])
    return out


def theta(b: BDD, state: list[list[int]], inverse: bool = False) -> list[list[int]]:
    parity = []
    for x in range(8):
        parity.append([
            b.xor(b.xor(state[0][x][z], state[1][x][z]), state[2][x][z])
            for z in range(64)
        ])
    if not inverse:
        effect = [
            [
                b.xor(rol(parity[(x - 1) % 8], THETA[0])[z],
                      rol(parity[(x - 1) % 8], THETA[1])[z])
                for z in range(64)
            ]
            for x in range(8)
        ]
    else:
        effect = parity[:]
        power = parity[:]
        for _ in range(64):
            power = [
                [
                    b.xor(rol(power[(x - 1) % 8], THETA[0])[z],
                          rol(power[(x - 1) % 8], THETA[1])[z])
                    for z in range(64)
                ]
                for x in range(8)
            ]
            effect = [
                [b.xor(effect[x][z], power[x][z]) for z in range(64)]
                for x in range(8)
            ]
    return [
        [[b.xor(state[y][x][z], effect[x][z]) for z in range(64)]
         for x in range(8)]
        for y in range(3)
    ]


def iota(b: BDD, state: list[list[int]], rc: int) -> list[list[int]]:
    out = [row[:] for row in state]
    for z in range(64):
        if (rc >> z) & 1:
            out[0][0][z] = b.not_(out[0][0][z])
    return out


def round_fwd(b: BDD, state: list[list[int]], rc: int) -> list[list[int]]:
    state = iota(b, state, rc)
    state = chi3(b, state)
    state = rho(state)
    state = theta(b, state)
    return rho(state)


def round_inv(b: BDD, state: list[list[int]], rc: int) -> list[list[int]]:
    state = rho(state, inverse=True)
    state = theta(b, state, inverse=True)
    state = rho(state, inverse=True)
    state = inv_chi3(b, state)
    return iota(b, state, rc)


def initial_state(b: BDD) -> list[list[int]]:
    state = [[[0] * 64 for _ in range(8)] for _ in range(3)]
    state[0][0] = b.vars[:]
    return state


def count_nonzero(b: BDD, state: list[list[int]]) -> list[tuple[int, int, int]]:
    return [(y, x, z) for y in range(3) for x in range(8) for z in range(64)
            if state[y][x][z] != 0]


def endpoint_sum(b: BDD, inverse: bool) -> tuple[list[tuple[int, int, int]], int]:
    state = initial_state(b)
    rounds = range(0, -6, -1) if inverse else range(1, 7)
    for step, ri in enumerate(rounds, 1):
        state = round_inv(b, state, ri) if inverse else round_fwd(b, state, ri)
        print(f"{'inverse' if inverse else 'forward'} round {step}: "
              f"{len(b.var)} BDD nodes", flush=True)
    nonzero = count_nonzero(b, state)
    parity = [(y, x, z) for y, x, z in nonzero if b.parity_all(state[y][x][z])]
    return parity, len(b.var)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--direction", choices=("forward", "inverse", "both"), default="both")
    parser.add_argument("--timeout", type=float, default=240)
    args = parser.parse_args()
    results = []
    for inverse in ((False, True) if args.direction == "both" else
                    (True,) if args.direction == "inverse" else (False,)):
        b = BDD(64)
        start = time.monotonic()
        try:
            parity, nodes = endpoint_sum(b, inverse)
            results.append({
                "direction": "inverse" if inverse else "forward",
                "completed": True,
                "nodes": nodes,
                "nonzero_coordinates": 192,
                "nonzero_parity_coordinates": parity,
                "elapsed_seconds": round(time.monotonic() - start, 3),
            })
        except MemoryError:
            results.append({"direction": "inverse" if inverse else "forward",
                            "completed": False, "error": "MemoryError",
                            "nodes": len(b.var),
                            "elapsed_seconds": round(time.monotonic() - start, 3)})
        if time.monotonic() - start > args.timeout:
            break
    import json
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
