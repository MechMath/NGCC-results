#!/usr/bin/env python3
"""One predeclared exact finite-field Groebner attempt on the 11-plane slice.

The homogeneous slice contains the hidden L2-intersection line with probability
one.  Work in the projective affine chart t_10 = 1.  This script preserves
timeouts and failures; a Groebner timeout proves neither emptiness nor security.
"""

import json
import signal
import sys
import time
from pathlib import Path

from sympy import Poly, groebner, symbols


class SolverTimeout(Exception):
    pass


def timeout_handler(_signum, _frame):
    raise SolverTimeout("120-second exact solver limit")


def monomials():
    return [(i, j, k)
            for i in range(11)
            for j in range(i, 11)
            for k in range(j, 11)]


def main():
    path = Path(sys.argv[1] if len(sys.argv) > 1 else "native/k2_slice.json")
    data = json.loads(path.read_text())
    if data["q"] != 65519 or data["slice_dim"] != 11:
        raise SystemExit("unexpected slice")
    if data["hidden_intersection_dim"] != 1:
        raise SystemExit("predeclared slice does not have one hidden line")

    mono = monomials()
    xs = symbols("t0:10")
    polys = []
    for eq in data["equations"]:
        poly = 0
        for coeff, (i, j, k) in zip(eq, mono):
            if not coeff:
                continue
            term = coeff
            if i == 10:
                term = 1
            else:
                term *= xs[i]
            if j == 10:
                pass
            else:
                term *= xs[j]
            if k == 10:
                pass
            else:
                term *= xs[k]
            poly += term
        polys.append(Poly(poly, *xs, modulus=data["q"]))

    started = time.monotonic()
    signal.signal(signal.SIGALRM, timeout_handler)
    signal.alarm(120)
    try:
        basis = groebner(polys, *xs, modulus=data["q"], order="grevlex")
        elapsed = time.monotonic() - started
        signal.alarm(0)
        out = {
            "schema": "facto-dsa-k2-slice-solver/v1",
            "status": "completed",
            "chart": "t10=1",
            "block_seconds": 120,
            "elapsed_seconds": elapsed,
            "basis_size": len(basis.polys),
            "basis": [str(p.as_expr() % data["q"]) for p in basis.polys],
            "note": "Completed basis is not a proof of complete enumeration.",
        }
    except SolverTimeout as exc:
        signal.alarm(0)
        out = {
            "schema": "facto-dsa-k2-slice-solver/v1",
            "status": "timeout",
            "chart": "t10=1",
            "block_seconds": 120,
            "elapsed_seconds": time.monotonic() - started,
            "error": str(exc),
            "note": "Timeout proves neither an empty intersection nor security.",
        }
    except Exception as exc:
        signal.alarm(0)
        out = {
            "schema": "facto-dsa-k2-slice-solver/v1",
            "status": "error",
            "chart": "t10=1",
            "block_seconds": 120,
            "elapsed_seconds": time.monotonic() - started,
            "error_type": type(exc).__name__,
            "error": str(exc),
            "note": "Solver error proves neither an empty intersection nor security.",
        }
    print(json.dumps(out, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
