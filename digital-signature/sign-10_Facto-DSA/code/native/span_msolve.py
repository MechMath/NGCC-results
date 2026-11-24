#!/usr/bin/env python3
"""Build and run one bounded msolve attempt on the frozen signature span."""

import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path


DIM = 13
Q = 65519


def monomials():
    return [(i, j, k) for i in range(DIM)
            for j in range(i, DIM) for k in range(j, DIM)]


def term(coeff, exponents):
    counts = {}
    for i in exponents:
        counts[i] = counts.get(i, 0) + 1
    factors = []
    for i in range(DIM):
        count = counts.get(i, 0)
        if count:
            factors.append(f"t{i}" if count == 1 else f"t{i}^{count}")
    body = "*".join(factors)
    return str(coeff) if not body else f"{coeff}*{body}"


def main():
    case_path = Path(sys.argv[1] if len(sys.argv) > 1 else "native/span_case.json")
    data = json.loads(case_path.read_text())
    if data["q"] != Q or data["span_dim"] != DIM or data["span_rank"] != DIM:
        raise SystemExit("unexpected or rank-deficient span")

    pk = bytes.fromhex(data["pk_hex"])
    columns = data["span_columns"]
    target = data["target"]
    mono = monomials()
    mono_pos = {exp: i for i, exp in enumerate(mono)}
    # Public coefficient order is i<=j<=k over all 20 coordinates.
    index = {}
    pos = 0
    for i in range(20):
        for j in range(i, 20):
            for k in range(j, 20):
                index[(i, j, k)] = pos
                pos += 1

    equations = [[0 for _ in mono] for _ in range(13)]
    full_mono = []
    full_index = {}
    full_pos = 0
    for i in range(20):
        for j in range(i, 20):
            for k in range(j, 20):
                full_mono.append((i, j, k))
                full_index[(i, j, k)] = full_pos
                full_pos += 1
    for i in range(20):
        for j in range(i, 20):
            for k in range(j, 20):
                src = index[(i, j, k)]
                for r in range(13):
                    off = (r * pos + src) * 2
                    c = pk[off] | (pk[off + 1] << 8)
                    if not c:
                        continue
                    for a in range(DIM):
                        xa = columns[a][i]
                        if not xa:
                            continue
                        for b in range(DIM):
                            xb = columns[b][j]
                            if not xb:
                                continue
                            cab = c * xa * xb % Q
                            for d in range(DIM):
                                xd = columns[d][k]
                                if not xd:
                                    continue
                                ex = tuple(sorted((a, b, d)))
                                dst = mono_pos[ex]
                                equations[r][dst] = (
                                    equations[r][dst] + cab * xd) % Q

    # Positive control: substituting each basis vector must reproduce the
    # direct public-map evaluation of the corresponding signer output.
    for basis in range(DIM):
        direct = [0] * 13
        for exp, src in full_index.items():
            prod = 1
            for variable in exp:
                prod = prod * columns[basis][variable] % Q
            for r in range(13):
                off = (r * full_pos + src) * 2
                c = pk[off] | (pk[off + 1] << 8)
                direct[r] = (direct[r] + c * prod) % Q
        diagonal = mono_pos[(basis, basis, basis)]
        restricted = [row[diagonal] for row in equations]
        if direct != restricted:
            raise SystemExit(
                f"restricted-equation control failed at basis {basis}")

    if "--selfcheck" in sys.argv[2:]:
        print(json.dumps({
            "schema": "facto-dsa-128-signature-span-equation-check/v1",
            "status": "passed",
            "basis_vectors_checked": DIM,
            "equations_checked_per_basis": 13,
            "case_sha256": hashlib.sha256(case_path.read_bytes()).hexdigest()
        }, indent=2, sort_keys=True))
        return

    polynomials = []
    for r in range(13):
        terms = [term(c, exp) for c, exp in zip(equations[r], mono)
                 if c]
        terms.append(str((-target[r]) % Q))
        polynomials.append("+".join(terms))

    input_path = Path("native/span_msolve_input.txt")
    output_path = Path("native/span_msolve_output.txt")
    input_path.write_text(
        ",".join(f"t{i}" for i in range(DIM)) + "\n" +
        str(Q) + "\n" + ",\n".join(polynomials) + "\n")

    libdir = Path("native/msolve_local/root/usr/lib/x86_64-linux-gnu").resolve()
    exe = Path("native/msolve_local/root/usr/bin/msolve").resolve()
    env = os.environ.copy()
    env["LD_LIBRARY_PATH"] = str(libdir)
    started = time.monotonic()
    timeout = 240
    try:
        proc = subprocess.run(
            [str(exe), "-f", str(input_path.resolve()),
             "-o", str(output_path.resolve()), "-t", "2", "-v", "1", "-l", "2"],
            env=env, capture_output=True, text=True, timeout=timeout,
            check=False)
        status = "completed" if proc.returncode == 0 else "error"
        result = {
            "schema": "facto-dsa-128-signature-span-msolve/v1",
            "status": status,
            "returncode": proc.returncode,
            "elapsed_seconds": time.monotonic() - started,
            "timeout_seconds": timeout,
            "input_sha256": hashlib.sha256(input_path.read_bytes()).hexdigest(),
            "output_sha256": (
                hashlib.sha256(output_path.read_bytes()).hexdigest()
                if output_path.exists() else None),
            "stdout": proc.stdout[-8000:],
            "stderr": proc.stderr[-8000:],
            "output": output_path.read_text()[:50000]
                      if output_path.exists() else "",
            "note": "Only a full untouched sig_verify acceptance is a forgery."
        }
    except subprocess.TimeoutExpired as exc:
        result = {
            "schema": "facto-dsa-128-signature-span-msolve/v1",
            "status": "timeout",
            "elapsed_seconds": time.monotonic() - started,
            "timeout_seconds": timeout,
            "input_sha256": hashlib.sha256(input_path.read_bytes()).hexdigest(),
            "output_sha256": (
                hashlib.sha256(output_path.read_bytes()).hexdigest()
                if output_path.exists() else None),
            "stdout": (exc.stdout or "")[-8000:]
                      if isinstance(exc.stdout, str) else "",
            "stderr": (exc.stderr or "")[-8000:]
                      if isinstance(exc.stderr, str) else "",
            "output": output_path.read_text()[:50000]
                      if output_path.exists() else "",
            "note": "Timeout is unresolved, not an impossibility or security proof."
        }
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
