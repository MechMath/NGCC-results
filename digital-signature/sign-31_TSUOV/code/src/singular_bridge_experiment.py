#!/usr/bin/env python3
"""Exact small-field audit of the reduced singular-point -> one-vector bridge.

This script deliberately uses exhaustive enumeration over tiny prime fields.
It is a mechanism check, not evidence about TSUOV security or timings.
"""

from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import math
import random
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence


Vector = tuple[int, ...]
Matrix = list[list[int]]


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def rank_mod_p(a: Sequence[Sequence[int]], p: int, rows: int | None = None) -> int:
    """Rank by Gauss-Jordan elimination over the prime field F_p."""
    if rows is None:
        rows = len(a)
    cols = len(a[0]) if a else 0
    m = [[a[i][j] % p for j in range(cols)] for i in range(rows)]
    r = 0
    for c in range(cols):
        pivot = next((i for i in range(r, rows) if m[i][c]), None)
        if pivot is None:
            continue
        m[r], m[pivot] = m[pivot], m[r]
        inv = pow(m[r][c], -1, p)
        m[r] = [(v * inv) % p for v in m[r]]
        for i in range(rows):
            if i != r and m[i][c]:
                q = m[i][c]
                m[i] = [(x - q * y) % p for x, y in zip(m[i], m[r])]
        r += 1
        if r == rows:
            break
    return r


def nullspace_mod_p(a: Sequence[Sequence[int]], p: int) -> list[Vector]:
    """Return a deterministic basis of the right nullspace of a."""
    rows = len(a)
    cols = len(a[0]) if a else 0
    m = [[a[i][j] % p for j in range(cols)] for i in range(rows)]
    pivots: list[int] = []
    r = 0
    for c in range(cols):
        pivot = next((i for i in range(r, rows) if m[i][c]), None)
        if pivot is None:
            continue
        m[r], m[pivot] = m[pivot], m[r]
        inv = pow(m[r][c], -1, p)
        m[r] = [(v * inv) % p for v in m[r]]
        for i in range(rows):
            if i != r and m[i][c]:
                q = m[i][c]
                m[i] = [(x - q * y) % p for x, y in zip(m[i], m[r])]
        pivots.append(c)
        r += 1
    free = [c for c in range(cols) if c not in pivots]
    basis: list[Vector] = []
    for f in free:
        v = [0] * cols
        v[f] = 1
        for i, c in enumerate(pivots):
            v[c] = (-m[i][f]) % p
        basis.append(tuple(v))
    return basis


def mat_vec(a: Sequence[Sequence[int]], x: Sequence[int], p: int) -> Vector:
    return tuple(sum(ai * xi for ai, xi in zip(row, x)) % p for row in a)


def quad(pmat: Sequence[Sequence[int]], x: Sequence[int], p: int) -> int:
    return sum(x[i] * pmat[i][j] * x[j] for i in range(len(x)) for j in range(len(x))) % p


def matmul(a: Sequence[Sequence[int]], b: Sequence[Sequence[int]], p: int) -> Matrix:
    return [
        [sum(a[i][k] * b[k][j] for k in range(len(b))) % p for j in range(len(b[0]))]
        for i in range(len(a))
    ]


def transpose(a: Sequence[Sequence[int]]) -> Matrix:
    return [list(x) for x in zip(*a)]


def inverse_mod_p(a: Sequence[Sequence[int]], p: int) -> Matrix:
    n = len(a)
    aug = [[a[i][j] % p for j in range(n)] + [int(i == j) for j in range(n)] for i in range(n)]
    for c in range(n):
        pivot = next((i for i in range(c, n) if aug[i][c]), None)
        if pivot is None:
            raise ValueError("singular matrix")
        aug[c], aug[pivot] = aug[pivot], aug[c]
        inv = pow(aug[c][c], -1, p)
        aug[c] = [(v * inv) % p for v in aug[c]]
        for i in range(n):
            if i != c and aug[i][c]:
                q = aug[i][c]
                aug[i] = [(x - q * y) % p for x, y in zip(aug[i], aug[c])]
    return [row[n:] for row in aug]


def span_dim(vectors: Iterable[Sequence[int]], p: int) -> int:
    vs = [tuple(v) for v in vectors if any(x % p for x in v)]
    return rank_mod_p(vs, p) if vs else 0


def in_span(v: Sequence[int], basis: Sequence[Sequence[int]], p: int) -> bool:
    return span_dim([*basis, v], p) == span_dim(basis, p)


def canonical_projective(x: Sequence[int], p: int) -> Vector | None:
    for v in x:
        if v % p:
            inv = pow(v % p, -1, p)
            return tuple((z * inv) % p for z in x)
    return None


def projective_points(n: int, p: int) -> Iterable[Vector]:
    """Enumerate P^(n-1)(F_p), represented by first nonzero coordinate 1."""
    for first in range(n):
        tail = n - first - 1
        for vals in itertools.product(range(p), repeat=tail):
            yield (0,) * first + (1,) + vals


def random_invertible(n: int, p: int, rng: random.Random) -> Matrix:
    # Product of random elementary row operations on a diagonal matrix.
    m = [[int(i == j) for j in range(n)] for i in range(n)]
    for i in range(n):
        q = rng.randrange(1, p)
        m[i] = [(q * v) % p for v in m[i]]
    for _ in range(3 * n * n):
        i, j = rng.sample(range(n), 2)
        q = rng.randrange(1, p)
        m[i] = [(x + q * y) % p for x, y in zip(m[i], m[j])]
    return m


def random_symmetric_q(n: int, zero_block: int, p: int, rng: random.Random) -> Matrix:
    a = [[0] * n for _ in range(n)]
    for i in range(n):
        for j in range(i, n):
            if i >= zero_block and j >= zero_block:
                continue
            a[i][j] = a[j][i] = rng.randrange(p)
    return a


@dataclass
class ToyUOV:
    p: int
    n: int
    o: int
    m: int
    r0: int
    public: list[Matrix]
    oil_basis: list[Vector]
    transform: Matrix
    seed: int


def toy_uov(p: int, n: int, o: int, m: int, seed: int) -> ToyUOV:
    if not (n > m + o and o >= 3 and m >= n - 2 * o + 2):
        raise ValueError("parameters must satisfy the reduced-system structural inequalities")
    rng = random.Random(seed)
    s = random_invertible(n, p, rng)
    si = inverse_mod_p(s, p)
    central = [random_symmetric_q(n, n - o, p, rng) for _ in range(m)]
    st = transpose(s)
    public = [matmul(matmul(st, f, p), s, p) for f in central]
    oil_basis = [tuple(si[i][n - o + j] for i in range(n)) for j in range(o)]
    return ToyUOV(p, n, o, m, n - 2 * o + 2, public, oil_basis, si, seed)


def singular_projective_points(toy: ToyUOV, retained: int) -> list[Vector]:
    points: list[Vector] = []
    for x in projective_points(toy.n, toy.p):
        if any(quad(toy.public[i], x, toy.p) for i in range(retained)):
            continue
        jac_rows = [
            tuple((2 * sum(toy.public[i][a][b] * x[b] for b in range(toy.n))) % toy.p
                  for a in range(toy.n))
            for i in range(retained)
        ]
        if rank_mod_p(jac_rows, toy.p, retained) < retained:
            points.append(x)
    return points


def is_oil(toy: ToyUOV, x: Sequence[int]) -> bool:
    return in_span(x, toy.oil_basis, toy.p)


def one_oil_vector_extract(toy: ToyUOV, x: Sequence[int]) -> list[Vector] | None:
    """Faithful small-field implementation of Algorithm 2a from hal-04215978."""
    jac = [tuple(x[j] for j in range(toy.n)) for _ in range(toy.m)]
    # Rows are x^T P_i.
    jac = [
        tuple(sum(x[a] * toy.public[i][a][b] for a in range(toy.n)) % toy.p
              for b in range(toy.n))
        for i in range(toy.m)
    ]
    kb = nullspace_mod_p(jac, toy.p)
    bmat = [[kb[j][i] for j in range(len(kb))] for i in range(toy.n)]
    bt = transpose(bmat)
    restricted = [matmul(matmul(bt, gi, toy.p), bmat, toy.p) for gi in toy.public]
    c: list[Vector] = []
    # Source stopping threshold is m; a generic instance reaches o independent
    # common-kernel vectors and then all later candidates are dependent.
    for gi in restricted:
        for z in nullspace_mod_p(gi, toy.p):
            if not in_span(z, c, toy.p):
                c.append(z)
                if len(c) == toy.m:
                    break
        if len(c) == toy.m:
            break
    lifted = [
        tuple(sum(bmat[i][j] * z[j] for j in range(len(kb))) % toy.p for i in range(toy.n))
        for z in c
    ]
    if span_dim(lifted, toy.p) != toy.o:
        return None
    # Validate, rather than trusting the cardinality.
    for z in lifted:
        if any(quad(gi, z, toy.p) for gi in toy.public):
            return None
    if span_dim([*lifted, *toy.oil_basis], toy.p) != toy.o:
        return None
    return lifted


def random_homogeneous_forms(count: int, n: int, p: int, rng: random.Random) -> Matrix:
    while True:
        forms = [[rng.randrange(p) for _ in range(n)] for _ in range(count)]
        if rank_mod_p(forms, p) == count:
            return forms


def dot(a: Sequence[int], b: Sequence[int], p: int) -> int:
    return sum(x * y for x, y in zip(a, b)) % p


def symbolic_part_i_counterexample() -> dict:
    """Check n=5,o=2,m=3 with p_i=u_i*o_1 over F_3."""
    p = 3
    public: list[Matrix] = []
    for i in range(3):
        a = [[0] * 5 for _ in range(5)]
        a[i][3] = a[3][i] = 1
        public.append(a)
    x = (0, 0, 0, 1, 0)
    rows = [
        tuple(sum((public[i][a][b] + public[i][b][a]) * x[b] for b in range(5)) % p
              for a in range(5))
        for i in range(3)
    ]
    r = rank_mod_p(rows, p)
    return {
        "n": 5,
        "o": 2,
        "m": 3,
        "O": "span(e4,e5)",
        "x": x,
        "all_forms_vanish_on_O": all(
            quad(g, (0, 0, 0, a, b), p) == 0
            for g in public for a in range(p) for b in range(p)
        ),
        "jacobian_rows_at_x": rows,
        "jacobian_rank": r,
        "codimension_of_regular_sequence": 3,
        "x_is_singular": r < 3,
    }


def hilbert_table_check(source_txt: Path) -> dict:
    """Expand the displayed bivariate series and compare with Table 1.

    The source's Table 1 reports (421,314,516,671). We separately record the
    literal table, the first total degree with non-positive homogeneous
    coefficient, and the source's operation formula at omega=2.
    """
    text = source_txt.read_text(encoding="utf-8", errors="replace")
    literal = "log2 ops 421 314 516 671" in text

    def homogeneous_coeffs(n: int, r: int, limit: int) -> list[int]:
        a: dict[int, int] = {}
        for i in range(n + 1):
            for x in range(n):
                for y in range(r):
                    d = 2 * i + x + y
                    if d <= limit:
                        a[d] = a.get(d, 0) + (
                            (-1) ** i * math.comb(n, i)
                            * math.comb(n + x - 1, x)
                            * math.comb(r + y - 1, y)
                        )
        # Multiply by (1-t1^2)^r. Keep the base separate from the result.
        base = a
        a = {}
        for j in range(1, r + 1):
            for d, c in base.items():
                if d + 2 * j <= limit:
                    a[d + 2 * j] = a.get(d + 2 * j, 0) + (-1) ** j * math.comb(r, j) * c
        for d, c in base.items():
            a[d] = a.get(d, 0) + c
        return [a.get(d, 0) for d in range(limit + 1)]

    rows = []
    expected = [421, 314, 516, 671]
    for (name, n, m, q), table_log2 in zip(
        [
            ("uov-Is", 160, 64, 16),
            ("uov-Ip", 112, 44, 256),
            ("uov-III", 184, 72, 256),
            ("uov-V", 244, 96, 256),
        ],
        expected,
    ):
        r = n - 2 * m + 2
        coeffs = homogeneous_coeffs(n, r, 130)
        dreg = next(d for d in range(1, len(coeffs)) if coeffs[d] <= 0)
        formula_log2 = math.log2(math.comb(n + r + dreg, dreg) ** 2)
        rows.append(
            {
                "name": name,
                "n": n,
                "m": m,
                "q": q,
                "r": r,
                "source_table_log2_ops": table_log2,
                "computed_dreg_total_degree": dreg,
                "computed_formula_log2_ops_omega_2": formula_log2,
                "matches_source_table": round(formula_log2) == table_log2,
            }
        )
    return {
        "source_table_literal_found": literal,
        "rows": rows,
        "reproduced": literal and all(x["matches_source_table"] for x in rows),
        "interpretation": (
            "A false reproduced flag is reported as a failed source-table reproduction; "
            "it is not repaired by choosing a degree that fits the table."
        ),
    }


def run_experiment(args: argparse.Namespace) -> dict:
    rng = random.Random(args.seed)
    table = hilbert_table_check(args.source_text)
    records = []
    totals = {
        "instances": 0,
        "singular_points": 0,
        "oil_singular_points": 0,
        "spurious_singular_points": 0,
        "slice_trials_2o_minus_1": 0,
        "slice_trials_o_minus_1": 0,
        "retained_oil_2o_minus_1": 0,
        "retained_oil_o_minus_1": 0,
        "affine_slice_trials": 0,
        "affine_slice_oil_hits": 0,
        "unique_total_o_minus_1": 0,
        "one_vector_successes": 0,
        "instances_with_no_rational_oil_singular_point": 0,
        "direct_one_oil_interface_successes": 0,
    }
    for key_index in range(args.keys):
        key_seed = args.seed * 10000 + key_index
        toy = toy_uov(args.p, args.n, args.o, args.m_full, key_seed)
        singular = singular_projective_points(toy, toy.r0)
        oil_points = [x for x in singular if is_oil(toy, x)]
        spurious = [x for x in singular if not is_oil(toy, x)]
        totals["instances"] += 1
        totals["singular_points"] += len(singular)
        totals["oil_singular_points"] += len(oil_points)
        totals["spurious_singular_points"] += len(spurious)
        if not oil_points:
            totals["instances_with_no_rational_oil_singular_point"] += 1
        for trial in range(args.slices):
            forms_2o = random_homogeneous_forms(2 * toy.o - 1, toy.n, toy.p, rng)
            forms_o = random_homogeneous_forms(toy.o - 1, toy.n, toy.p, rng)
            affine = [rng.randrange(toy.p) for _ in range(toy.n)]
            hits_2o = [x for x in singular if all(dot(h, x, toy.p) == 0 for h in forms_2o)]
            hits_o = [x for x in singular if all(dot(h, x, toy.p) == 0 for h in forms_o)]
            hits_affine = [x for x in singular if dot(affine, x, toy.p) == 1]
            totals["slice_trials_2o_minus_1"] += 1
            totals["slice_trials_o_minus_1"] += 1
            totals["affine_slice_trials"] += 1
            totals["retained_oil_2o_minus_1"] += sum(is_oil(toy, x) for x in hits_2o)
            totals["retained_oil_o_minus_1"] += sum(is_oil(toy, x) for x in hits_o)
            totals["affine_slice_oil_hits"] += sum(is_oil(toy, x) for x in hits_affine)
            if len(hits_o) == 1:
                totals["unique_total_o_minus_1"] += 1
            for x in hits_o:
                if is_oil(toy, x) and one_oil_vector_extract(toy, x):
                    totals["one_vector_successes"] += 1
                    break
            records.append(
                {
                    "key": key_index,
                    "trial": trial,
                    "hits_2o_minus_1": len(hits_2o),
                    "oil_hits_2o_minus_1": sum(is_oil(toy, x) for x in hits_2o),
                    "hits_o_minus_1": len(hits_o),
                    "oil_hits_o_minus_1": sum(is_oil(toy, x) for x in hits_o),
                }
            )
        # Test the OneOilVector interface independently of slice success.
        if oil_points:
            if one_oil_vector_extract(toy, oil_points[0]) is not None:
                totals["direct_one_oil_interface_successes"] += 1
    return {
        "environment": {
            "python": "stdlib-only exact arithmetic over F_p",
            "sources": {
                str(args.source_pdf): sha256(args.source_pdf),
                str(args.source_text): sha256(args.source_text),
            },
        },
        "parameters": {
            "p": args.p,
            "n": args.n,
            "o": args.o,
            "v": args.n - args.o,
            "m_full": args.m_full,
            "r0_reduced": args.n - 2 * args.o + 2,
            "keys": args.keys,
            "slice_trials_per_key": args.slices,
            "universe": f"all {(args.p ** args.n - 1) // (args.p - 1)} projective points of P^{args.n - 1}(F_{args.p})",
        },
        "hilbert_table": table,
        "part_i_symbolic_counterexample": symbolic_part_i_counterexample(),
        "totals": totals,
        "trial_records": records,
        "limits": [
            "Toy prime-field mechanism check only; no extrapolation to q=31^2 or Table 1 security.",
            "Exhaustive singular enumeration is only for the stated tiny finite universe.",
            "A failed slice or extraction is not a refutation of generic TSUOV key recovery.",
        ],
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--p", type=int, default=3)
    ap.add_argument("--n", type=int, default=10)
    ap.add_argument("--o", type=int, default=4)
    ap.add_argument("--m-full", type=int, default=5)
    ap.add_argument("--keys", type=int, default=20)
    ap.add_argument("--slices", type=int, default=100)
    ap.add_argument("--seed", type=int, default=20261120)
    ap.add_argument("--source-pdf", type=Path, default=Path("artifacts/pebereau-04454521.pdf"))
    ap.add_argument("--source-text", type=Path, default=Path("artifacts/pebereau-04454521.txt"))
    ap.add_argument("--output", type=Path, default=Path("out/singular-bridge-results.json"))
    args = ap.parse_args()
    result = run_experiment(args)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({k: v for k, v in result.items() if k != "trial_records"}, indent=2))
    print(f"wrote {args.output} sha256={sha256(args.output)}")


if __name__ == "__main__":
    main()
