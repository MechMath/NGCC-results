#!/usr/bin/env python3
"""Bounded exact bit-vector solve of the same predeclared 11-plane slice."""

import json
import sys
import time
from pathlib import Path

import z3


def monomials():
    return [(i, j, k)
            for i in range(11)
            for j in range(i, 11)
            for k in range(j, 11)]


def qmul(a, b, q):
    return z3.URem(a * b, z3.BitVecVal(q, 16))


def qadd(a, b, q):
    s = a + b
    return z3.If(z3.UGE(s, z3.BitVecVal(q, 16)),
                 s - z3.BitVecVal(q, 16), s)


def main():
    path = Path(sys.argv[1] if len(sys.argv) > 1 else "native/k2_slice.json")
    data = json.loads(path.read_text())
    if data["q"] != 65519 or data["slice_dim"] != 11:
        raise SystemExit("unexpected slice")
    if data["hidden_intersection_dim"] != 1:
        raise SystemExit("predeclared slice does not have one hidden line")

    q = data["q"]
    mono = monomials()
    xs = [z3.BitVec(f"t{i}", 16) for i in range(11)]
    solver = z3.Solver()
    solver.set(timeout=120000)
    for x in xs:
        solver.add(z3.ULT(x, z3.BitVecVal(q, 16)))
    solver.add(z3.Or(*[x != 0 for x in xs]))

    for eq in data["equations"]:
        acc = z3.BitVecVal(0, 16)
        for coeff, (i, j, k) in zip(eq, mono):
            if not coeff:
                continue
            term = z3.BitVecVal(coeff, 16)
            term = qmul(term, xs[i], q)
            term = qmul(term, xs[j], q)
            term = qmul(term, xs[k], q)
            acc = qadd(acc, term, q)
        solver.add(acc == z3.BitVecVal(0, 16))

    started = time.monotonic()
    result = solver.check()
    elapsed = time.monotonic() - started
    out = {
        "schema": "facto-dsa-k2-slice-z3/v1",
        "backend": f"z3 {z3.get_version_string()}",
        "block_seconds": 120,
        "elapsed_seconds": elapsed,
        "timeout_ms": 120000,
        "status": str(result),
        "statistics": str(solver.statistics()),
    }
    if result == z3.sat:
        model = solver.model()
        out["candidate_t"] = [model.eval(x).as_long() for x in xs]
    elif result == z3.unknown:
        out["reason_unknown"] = solver.reason_unknown()
    out["note"] = ("A timeout/unknown proves neither an empty intersection nor "
                   "security; a SAT candidate still requires exact C checks.")
    print(json.dumps(out, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
