#!/usr/bin/env python3
"""Search one-round ZC-1536-DM-512 capacity-collision traces.

This is discovery code.  It uses the literal per-lane equations from the
allowlisted specification, but only one of the specified twelve rounds.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

import z3


MASK64 = (1 << 64) - 1
ROUND_CONSTANTS = {
    -11: 0x0000000000000058,
    -10: 0x0000000000000038,
    -9: 0x00000000000003C0,
    -8: 0x00000000000000D0,
    -7: 0x0000000000000060,
    -6: 0x0000000000000120,
    -5: 0x0000000000000014,
    -4: 0x000000000000002C,
    -3: 0x00000000000000F0,
    -2: 0x00000000000001A0,
    -1: 0x0000000000000380,
    0: 0x0000000000000012,
}

# ZC-1536: state A[y][x], y=0..2, x=0..7, with bit z in each 64-bit lane.
NX = 8
NY = 3
RHO = ((0, 0), (3, 3), (5, 0))
THETA = (20, 56)
BITS = 64 * NX * NY
RATE = 960
CAPACITY = BITS - RATE


def zero_state():
    return [[0 for _ in range(NX)] for _ in range(NY)]


def rotr(v: int, n: int) -> int:
    return ((v >> n) | (v << (64 - n))) & MASK64


def lane_rot(v: int, n: int) -> int:
    n %= 64
    return ((v << n) | (v >> (64 - n))) & MASK64 if n else v


def rho(a):
    out = [row[:] for row in a]
    for y, (dx, dz) in enumerate(RHO):
        if not dx and not dz:
            continue
        row = [0] * NX
        for x in range(NX):
            row[(x + dx) % NX] = lane_rot(a[y][x], dz)
        out[y] = row
    return out


def chi(a):
    out = [row[:] for row in a]
    for y in range(NY):
        y1 = (y + 1) % NY
        y2 = (y + 2) % NY
        for x in range(NX):
            out[y][x] = a[y][x] ^ ((~a[y1][x]) & a[y2][x]) & MASK64
    return out


def theta(a):
    p = [0] * NX
    for y in range(NY):
        for x in range(NX):
            p[x] ^= a[y][x]
    pr = [0] * NX
    for x in range(NX):
        pr[(x + 1) % NX] = p[x]
    e = [lane_rot(pr[x], THETA[0]) ^ lane_rot(pr[x], THETA[1]) for x in range(NX)]
    return [[a[y][x] ^ e[x] for x in range(NX)] for y in range(NY)]


def iota(a, rc):
    out = [row[:] for row in a]
    out[0][0] = out[0][0] ^ rc
    return out


def rho_sym(a):
    out = [row[:] for row in a]
    for y, (dx, dz) in enumerate(RHO):
        if not dx and not dz:
            continue
        row = [None] * NX
        for x in range(NX):
            row[(x + dx) % NX] = z3.RotateLeft(a[y][x], dz) if dz else a[y][x]
        out[y] = row
    return out


def theta_sym(a):
    p = [z3.BitVecVal(0, 64) for _ in range(NX)]
    for y in range(NY):
        for x in range(NX):
            p[x] = p[x] ^ a[y][x]
    pr = [None] * NX
    for x in range(NX):
        pr[(x + 1) % NX] = p[x]
    e = [z3.RotateLeft(pr[x], THETA[0]) ^ z3.RotateLeft(pr[x], THETA[1]) for x in range(NX)]
    return [[a[y][x] ^ e[x] for x in range(NX)] for y in range(NY)]


def round_sym(a, rc):
    return rho_sym(theta_sym(rho_sym(chi(iota(a, z3.BitVecVal(rc, 64))))))


def variable_state(prefix):
    return [[z3.BitVec(f"{prefix}_{y}_{x}", 64) for x in range(NX)] for y in range(NY)]


def padded_rate_constraints(a):
    """Constrain the first r=960 implementation-ordered bits to a valid pad.

    The message length is r-4 bits, so the rate suffix is 01||11 = 0111.
    Leading bits use y-major, x, then MSB-to-LSB z order, as documented in
    the independent local reference.  The missing external serialization is a
    known specification ambiguity; this script fixes one explicitly.
    """
    out = []
    positions = [(y, x, 63 - bit) for y in range(NY) for x in range(NX) for bit in range(64)]
    assert len(positions) == BITS
    for pos, bit in zip(positions[:RATE][-4:], [0, 1, 1, 1]):
        y, x, z = pos
        out.append(z3.Extract(z, z, a[y][x]) == bit)
    # S0=M0||0^c.
    for y, x, z in positions[RATE:]:
        out.append(z3.Extract(z, z, a[y][x]) == 0)
    return out


def state_int(a):
    value = 0
    for y in range(NY):
        for x in range(NX):
            value |= a[y][x] << (64 * (y * NX + x))
    return value


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--timeout-ms", type=int, default=180000)
    parser.add_argument("--round-index", type=int, default=-11)
    parser.add_argument("--round-count", type=int, default=1)
    parser.add_argument("--seed", type=int, default=114)
    parser.add_argument("--output", type=Path, default=Path("reduced_collision_result.json"))
    args = parser.parse_args()

    x = variable_state("x")
    y = variable_state("y")
    def prefix_rounds(a):
        out = a
        for offset in range(args.round_count):
            out = round_sym(out, ROUND_CONSTANTS[args.round_index + offset])
        return out

    fx = prefix_rounds(x)
    fy = prefix_rounds(y)

    solver = z3.Solver()
    solver.set("timeout", args.timeout_ms)
    solver.add(padded_rate_constraints(x))
    solver.add(padded_rate_constraints(y))
    solver.add(z3.Or([x[yy][xx] != y[yy][xx] for yy in range(NY) for xx in range(NX)]))

    # F=round(x) xor x.  Equal capacity leaves the rate blocks free to
    # overwrite the difference in a second absorption transition.
    positions = [(yy, xx, 63 - bit) for yy in range(NY) for xx in range(NX) for bit in range(64)]
    for yy, xx, zz in positions[RATE:]:
        solver.add(z3.Extract(zz, zz, fx[yy][xx] ^ x[yy][xx])
                   == z3.Extract(zz, zz, fy[yy][xx] ^ y[yy][xx]))

    # Use raw messages of 1912 bits.  Their eight-bit padding suffix is
    # 01||1||0^4||1 = 01100001, so the two second blocks must have the same
    # suffix.  Their rate difference is F(x) xor F(y), requiring its last eight
    # bits to vanish; a common target rate can then be chosen.
    for yy, xx, zz in positions[RATE - 8:RATE]:
        solver.add(z3.Extract(zz, zz, (fx[yy][xx] ^ x[yy][xx])
                              ^ (fy[yy][xx] ^ y[yy][xx])) == 0)

    # Break global-complement symmetries without excluding a valid trace.
    solver.add(x[0][0] & 0xFFFF == 0)

    status = solver.check()
    result = {
        "scope": {
            "profile": "ZC-1536-DM-512",
            "rounds": args.round_count,
            "round_count": args.round_count,
            "round_index": args.round_index,
            "preserved": [
                "literal iota/chi/rho/theta/rho equations",
                "m=1536, n=512, c=576, r=960",
                "zero-capacity initial-state form M0||0^c",
                "one-block padding suffix 0111 at maximal payload",
                "two-block absorption and final Davies-Meyer feed-forward",
            ],
            "omitted": [
                f"rounds {args.round_count + 1} through 12 of the specified permutation"
            ],
            "serialization": "explicit y-major, x, MSB-first within lane",
        },
        "solver": {"name": "z3", "version": z3.get_version_string(), "status": str(status)},
    }
    if status == z3.sat:
        mx = solver.model()
        xv = [[mx.eval(x[yy][xx]).as_long() for xx in range(NX)] for yy in range(NY)]
        yv = [[mx.eval(y[yy][xx]).as_long() for xx in range(NX)] for yy in range(NY)]
        def concrete_prefix_rounds(a):
            out = a
            for offset in range(args.round_count):
                out = round_function(out, ROUND_CONSTANTS[args.round_index + offset])
            return out

        fxv = concrete_prefix_rounds(xv)
        fyv = concrete_prefix_rounds(yv)
        result["witness"] = {
            "x_lanes_hex": [[hex(v) for v in row] for row in xv],
            "y_lanes_hex": [[hex(v) for v in row] for row in yv],
            "x_state_hex": hex(state_int(xv)),
            "y_state_hex": hex(state_int(yv)),
            "cap_fx_hex": hex(sum(
                ((fxv[yy][xx] ^ xv[yy][xx]) >> (63 - bit) & 1) << index
                for index, (yy, xx, bit) in enumerate(positions[RATE:])
            )),
            "cap_fy_hex": hex(sum(
                ((fyv[yy][xx] ^ yv[yy][xx]) >> (63 - bit) & 1) << index
                for index, (yy, xx, bit) in enumerate(positions[RATE:])
            )),
        }
    elif status == z3.unknown:
        result["reason_unknown"] = solver.reason_unknown()

    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if status == z3.sat else 1


def round_function(a, rc):
    return rho(theta(rho(chi(iota(a, rc)))))


if __name__ == "__main__":
    raise SystemExit(main())
