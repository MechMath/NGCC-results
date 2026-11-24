#!/usr/bin/env python3
"""Solve the frozen 11-plane slice after a predeclared random hyperplane cut."""

import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path


def monomials():
    return [(i, j, k)
            for i in range(11)
            for j in range(i, 11)
            for k in range(j, 11)]


def term(coeff, exponents):
    factors = [f"t{i}" for i in exponents if exponents.count(i) == 1]
    counts = {i: exponents.count(i) for i in set(exponents)}
    factors = []
    for i in range(11):
        count = counts.get(i, 0)
        if count == 1:
            factors.append(f"t{i}")
        elif count == 2:
            factors.append(f"t{i}^2")
        elif count == 3:
            factors.append(f"t{i}^3")
        elif count > 3:
            raise ValueError("degree too high")
    body = "*".join(factors)
    return str(coeff) if not body else f"{coeff}*{body}"


def main():
    path = Path(sys.argv[1] if len(sys.argv) > 1 else "native/k2_slice.json")
    affine = "--affine" in sys.argv[2:]
    data = json.loads(path.read_text())
    if data["q"] != 65519 or data["slice_dim"] != 11:
        raise SystemExit("unexpected slice")
    if data["hidden_intersection_dim"] != 1:
        raise SystemExit("predeclared slice does not have one hidden line")

    mono = monomials()
    polynomials = []
    for equation in data["equations"]:
        terms = [term(c, exponents)
                 for c, exponents in zip(equation, mono) if c]
        polynomials.append("+".join(terms))

    variables = list(range(11))
    if affine:
        # The dump fixed a hidden intersection vector with t10=1.  Substituting
        # this chart preserves that nonzero point and removes the non-isolated
        # projective line direction.
        variables = list(range(10))
    else:
        # A homogeneous linear cut only meets a non-contained line at the zero
        # vector.  This branch is retained as the failed first formulation.
        digest = hashlib.sha256(b"facto-dsa-k2-msolve-hyperplane-v1").digest()
        hyperplane = "+".join(
            f"{int.from_bytes(digest[2*i:2*i+2], 'little') % data['q']}*t{i}"
            for i in range(11))
        polynomials.append(hyperplane)

    input_path = Path("native/k2_slice_msolve_affine_input.txt" if affine
                      else "native/k2_slice_msolve_input.txt")
    output_path = Path("native/k2_slice_msolve_affine_output.txt" if affine
                       else "native/k2_slice_msolve_output.txt")
    if affine:
        rewritten = []
        for equation in data["equations"]:
            terms = []
            for c, exponents in zip(equation, mono):
                if not c:
                    continue
                factors = []
                for i in exponents:
                    if i < 10:
                        factors.append(f"t{i}")
                body = "*".join(factors)
                terms.append(str(c) if not body else f"{c}*{body}")
            rewritten.append("+".join(terms))
        polynomials = rewritten
    input_path.write_text(
        ",".join(f"t{i}" for i in variables) + "\n" +
        str(data["q"]) + "\n" +
        ",\n".join(polynomials) + "\n"
    )
    libdir = Path("native/msolve_local/root/usr/lib/x86_64-linux-gnu").resolve()
    exe = Path("native/msolve_local/root/usr/bin/msolve").resolve()
    env = os.environ.copy()
    env["LD_LIBRARY_PATH"] = str(libdir)
    started = time.monotonic()
    timeout_seconds = 600 if affine else 180
    try:
        proc = subprocess.run(
            [str(exe), "-f", str(input_path.resolve()), "-o", str(output_path.resolve()),
             "-t", "2", "-v", "1", "-l", "2"],
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
        elapsed = time.monotonic() - started
        status = "completed" if proc.returncode == 0 else "error"
        result = {
            "schema": "facto-dsa-k2-slice-msolve/v1",
            "backend": "msolve 0.6.5",
            "status": status,
            "returncode": proc.returncode,
            "elapsed_seconds": elapsed,
            "timeout_seconds": timeout_seconds,
            "stdout": proc.stdout[-10000:],
            "stderr": proc.stderr[-10000:],
            "input_sha256": hashlib.sha256(input_path.read_bytes()).hexdigest(),
            "output_sha256": (
                hashlib.sha256(output_path.read_bytes()).hexdigest()
                if output_path.exists() else None
            ),
            "output": output_path.read_text()[:50000] if output_path.exists() else None,
            "note": "Any solver point still requires exact public and C verification.",
        }
    except subprocess.TimeoutExpired as exc:
        result = {
            "schema": "facto-dsa-k2-slice-msolve/v1",
            "backend": "msolve 0.6.5",
            "status": "timeout",
            "elapsed_seconds": time.monotonic() - started,
            "timeout_seconds": timeout_seconds,
            "stdout": (exc.stdout or "")[-10000:] if isinstance(exc.stdout, str)
                      else "",
            "stderr": (exc.stderr or "")[-10000:] if isinstance(exc.stderr, str)
                      else "",
            "input_sha256": hashlib.sha256(input_path.read_bytes()).hexdigest(),
            "output_sha256": (
                hashlib.sha256(output_path.read_bytes()).hexdigest()
                if output_path.exists() else None
            ),
            "output": output_path.read_text()[:50000] if output_path.exists() else None,
            "note": "Timeout proves neither an empty intersection nor security.",
        }
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
