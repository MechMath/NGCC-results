#!/usr/bin/env python3
"""Diagnostic SAT search for a six-round ZC-1536 differential characteristic.

The model uses the exact 3-bit chi DDT and exact linear diffusion.  A model is a
characteristic, not a concrete input pair.
"""

import sys
import time

import z3


def chi3(x):
    return [
        x[0] ^ z3.Not(x[1]) & x[2],
        x[1] ^ z3.Not(x[2]) & x[0],
        x[2] ^ z3.Not(x[0]) & x[1],
    ]


def chi3_value(x):
    return [
        x[0] ^ ((1 ^ x[1]) & x[2]),
        x[1] ^ ((1 ^ x[2]) & x[0]),
        x[2] ^ ((1 ^ x[0]) & x[1]),
    ]


DDT = {}
for a in range(8):
    for x in range(8):
        b = chi3_value([(x >> i) & 1 for i in range(3)])
        y = x ^ a
        c = chi3_value([(y >> i) & 1 for i in range(3)])
        out = sum((b[i] ^ c[i]) << i for i in range(3))
        DDT[a, out] = DDT.get((a, out), 0) + 1


def state(prefix):
    return {
        (y, x, z): z3.Bool(f"{prefix}_{x}_{y}_{z}")
        for y in range(3)
        for x in range(8)
        for z in range(64)
    }


def sbox_layer(s, solver, tag):
    out = {}
    active = []
    for x in range(8):
        for z in range(64):
            a = [s[y, x, z] for y in range(3)]
            b = [z3.Bool(f"c_{tag}_{x}_{y}_{z}") for y in range(3)]
            av = z3.Sum([z3.If(v, 1 << i, 0) for i, v in enumerate(a)]) if False else None
            # Compare the six-bit concatenation without arithmetic.  One Bool
            # selector per possible DDT output is compact enough at this size.
            for y in range(3):
                out[y, x, z] = b[y]
            active.append(z3.Or(*a))
            cases = []
            for ai in range(8):
                for bi in range(8):
                    if (ai, bi) not in DDT:
                        continue
                    cond = []
                    for i in range(3):
                        cond.append(a[i] if (ai >> i) & 1 else z3.Not(a[i]))
                        cond.append(b[i] if (bi >> i) & 1 else z3.Not(b[i]))
                    cases.append(z3.And(*cond))
            solver.add(z3.Or(*cases))
    return out, active


def rho(s):
    shifts = [0, 3, 5]
    out = {}
    for y in range(3):
        for x in range(8):
            for z in range(64):
                srcx = (x - shifts[y]) % 8
                srcz = (z - shifts[y]) % 64
                out[y, x, z] = s[y, srcx, srcz]
    return out


def theta(s):
    p = {}
    for x in range(8):
        for z in range(64):
            p[x, z] = s[0, x, z] ^ s[1, x, z] ^ s[2, x, z]
    out = {}
    for y in range(3):
        for x in range(8):
            for z in range(64):
                srcx = (x - 1) % 8
                out[y, x, z] = s[y, x, z] ^ p[srcx, (z - 20) % 64] ^ p[srcx, (z - 56) % 64]
    return out


def round_diff(s, solver, tag):
    s, active = sbox_layer(s, solver, tag)
    s = rho(s)
    s = theta(s)
    s = rho(s)
    return s, active


def main():
    half = sys.argv[1] if len(sys.argv) > 1 else "g"
    m = 1536
    c = int(sys.argv[2]) if len(sys.argv) > 2 else 576
    timeout_ms = int(sys.argv[3]) if len(sys.argv) > 3 else 300000
    r = m - c
    d = state("d")
    s = d
    active_bound = int(sys.argv[4]) if len(sys.argv) > 4 else None
    solver = z3.Solver()
    solver.set(timeout=timeout_ms)
    if len(sys.argv) > 5:
        solver.set("random_seed", int(sys.argv[5]))
    rounds = range(-11, -5) if half == "g" else range(-5, 1)
    active_all = []
    for rn, _ in enumerate(rounds):
        s, active = round_diff(s, solver, rn)
        active_all.extend(active)
    for y in range(3):
        for x in range(8):
            for z in range(64):
                t = 64 * (3 * x + y) + z
                if t < r:
                    solver.add(z3.Not(s[y, x, z]))
                else:
                    solver.add(s[y, x, z] == d[y, x, z])
    # Lemma 8c9b80bca9407a47: a distinct Q_K solution must have a
    # nonzero capacity difference.  An all-rate difference cannot lift:
    # L(Delta)=0 would make K(X xor Delta)=K(X), hence Delta=0.
    cap_difference = [
        d[y, x, z]
        for y in range(3)
        for x in range(8)
        for z in range(64)
        if 64 * (3 * x + y) + z >= r
    ]
    solver.add(z3.Or(*cap_difference))
    objective = z3.Sum([z3.If(v, 1, 0) for v in active_all])
    if active_bound is not None:
        solver.add(objective <= active_bound)
    start = time.time()
    result = solver.check()
    print(f"half={half} c={c} result={result} elapsed={time.time()-start:.3f}s")
    if result == z3.sat:
        model = solver.model()
        active = 0
        for y in range(3):
            for x in range(8):
                for z in range(64):
                    if z3.is_true(model.eval(d[y, x, z], model_completion=True)):
                        active += 1
        print("input_weight=", active)
        print("active_sboxes=", model.eval(objective, model_completion=True))
        print("capacity_nonzero=", model.eval(z3.Or(*cap_difference), model_completion=True))
        print("TRUE_D=" + " ".join(
            f"({y},{x},{z})"
            for y in range(3) for x in range(8) for z in range(64)
            if z3.is_true(model.eval(d[y, x, z], model_completion=True))
        ))
        # Save only a compact model diagnostic in the process output.
        words = []
        for x in range(8):
            for y in range(3):
                w = 0
                for z in range(64):
                    if z3.is_true(model.eval(d[y, x, z], model_completion=True)):
                        w |= 1 << z
                words.append(w)
        print("D_LANES=" + " ".join(f"{w:016x}" for w in words))


if __name__ == "__main__":
    main()
