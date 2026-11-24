#!/usr/bin/env python3
"""Exact difference model for six ZC-1536 rounds.

This is a local diagnostic.  It proves nothing unless a returned model is
independently replayed; solver output is retained as notes, not run evidence.
"""

import sys
import z3

XDIM = 8
YDIM = 3
BITS = 1536
LANES = XDIM * YDIM


def as_bool(bit):
    return z3.BoolVal(bit) if isinstance(bit, (bool, int)) else bit


def idx(x, y, z):
    return 64 * (3 * x + y) + z


def chi3(v):
    return tuple(
        (v[i] ^ ((1 ^ v[(i + 1) % 3]) & v[(i + 2) % 3])) & 1
        for i in range(3)
    )


DDT = {}
for din in range(8):
    outs = set()
    for xv in range(8):
        xbits = tuple((xv >> i) & 1 for i in range(3))
        xdbits = tuple(((xv ^ din) >> i) & 1 for i in range(3))
        outs.add(tuple(a ^ b for a, b in zip(chi3(xbits), chi3(xdbits))))
    DDT[din] = tuple(sorted(outs))


def word_bits(word):
    return [(word >> z) & 1 for z in range(64)]


def rho(state):
    out = [None] * BITS
    shifts = ((0, 0), (3, 3), (5, 0))
    for x in range(XDIM):
        for y in range(YDIM):
            a, b = shifts[y]
            for z in range(64):
                out[idx(x, y, z)] = state[
                    idx((x - a) % XDIM, y, (z - b) % 64)
                ]
    return out


def theta(state):
    parity = {}
    for x in range(XDIM):
        for z in range(64):
            parity[x, z] = z3.Xor(
                *[as_bool(state[idx(x, y, z)]) for y in range(YDIM)]
            )
    effect = {}
    for x in range(XDIM):
        for z in range(64):
            effect[x, z] = z3.Xor(
                parity[(x - 1) % XDIM, (z - 20) % 64],
                parity[(x - 1) % XDIM, (z - 56) % 64],
            )
    out = [None] * BITS
    for x in range(XDIM):
        for y in range(YDIM):
            for z in range(64):
                out[idx(x, y, z)] = z3.Xor(
                    as_bool(state[idx(x, y, z)]), effect[x, z]
                )
    return out


def chi_difference(state, round_index, active_cells=None):
    out = [None] * BITS
    for x in range(XDIM):
        for z in range(64):
            din = [as_bool(state[idx(x, y, z)]) for y in range(YDIM)]
            dint = z3.Sum(
                *[z3.If(din[y], 1, 0) * (1 << y) for y in range(YDIM)]
            )
            choices = []
            outs_vars = [
                z3.Bool(f"chi_d_{round_index}_{x}_{z}_{y}")
                for y in range(YDIM)
            ]
            outt = z3.Sum(
                *[z3.If(outs_vars[y], 1, 0) * (1 << y) for y in range(YDIM)]
            )
            for dval, possible in DDT.items():
                choices.append(z3.And(
                    dint == dval,
                    z3.Or(*[
                        outt == sum(v[i] << i for i in range(3))
                        for v in possible
                    ]),
                ))
            z3.solver_extra.append(z3.Or(*choices))
            if active_cells is not None:
                # The S-box is active exactly when both its input and output
                # differences are nonzero.  The latter is part of feasibility.
                active_cells.append(z3.And(
                    dint != 0, outt != 0
                ))
            for y in range(YDIM):
                out[idx(x, y, z)] = outs_vars[y]
    return out


def main():
    budget = int(sys.argv[1]) if len(sys.argv) > 1 else 96
    z3.solver_extra = []
    sol = z3.Solver()
    sol.set(timeout=180000)

    states = []
    first = [z3.Bool(f"d0_{i}") for i in range(BITS)]
    delta_word = 0x8888888888888888
    for z, bit in enumerate(word_bits(delta_word)):
        sol.add(first[idx(7, 0, z)] == bool(bit))
    states.append(first)

    active = []
    for r in range(6):
        cur = states[-1]
        nxt = chi_difference(cur, r, active)
        nxt = rho(theta(rho(nxt)))
        states.append(nxt)
    for c in z3.solver_extra:
        sol.add(c)

    # Q boundary: output difference = L(input difference), through six rounds.
    for i in range(BITS):
        expected = False if i < 960 else first[i]
        sol.add(states[6][i] == expected)
    sol.add(z3.PbLe([(a, 1) for a in active], budget))

    print(f"cells={len(active)} budget={budget}", flush=True)
    result = sol.check()
    print(result, flush=True)
    if result == z3.sat:
        model = sol.model()
        count = 0
        hexes = []
        for r, st in enumerate(states):
            lane_vals = []
            for lane in range(LANES):
                v = 0
                for z in range(64):
                    if z3.is_true(model.eval(st[lane * 64 + z], model_completion=True)):
                        v |= 1 << z
                lane_vals.append(v)
                count += sum(bool((v >> z) & 1) for z in range(64))
            hexes.append(lane_vals)
            print(f"round {r}: " + " ".join(f"{v:016x}" for v in lane_vals))
        print("active_bound", budget)
        print("total_active_constraints", len(active))
        print("state_weight", count)


if __name__ == "__main__":
    main()
