#!/usr/bin/env python3
"""Exact structural checks for the Facto-DSA-128 submitted test vector.

This script uses the original KAT file only for ground truth.  Candidate
algorithms in this project must not consume the secret key.
"""

from __future__ import annotations

import argparse
import hashlib
import random
from pathlib import Path


Q = 65519
N = 10
R = 2 * N
D = 2 * N - 1
M = 13
S_OUT = D - M

SK_SINV_OFFSET = 0
SK_SINV_ELEMS = R * R
SK_U_OFFSET = SK_SINV_OFFSET + 2 * SK_SINV_ELEMS
SK_U_ELEMS = D * M
SK_K_OFFSET = SK_U_OFFSET + 2 * SK_U_ELEMS
SK_K_ELEMS = S_OUT * D
SK_Q_OFFSET = SK_K_OFFSET + 2 * SK_K_ELEMS
SK_Q_ELEMS = (N + 2) * (N + 1) * N // 6
SK_R_OFFSET = SK_Q_OFFSET + 2 * SK_Q_ELEMS
SK_R_ELEMS = N * (N * (N + 1) // 2)

TRIPLES = [(i, j, k) for i in range(R) for j in range(i, R) for k in range(j, R)]


def kub(i: int, j: int, k: int) -> int:
    i, j, k = sorted((i, j, k))
    idx = 0
    for a in range(i):
        idx += (R - a + 1) * (R - a) // 2
    for b in range(i, j):
        idx += R - b
    return idx + k - j


def parse_kat(path: Path, count: int = 0) -> dict[str, bytes]:
    wanted = f"Count = {count}"
    fields: dict[str, bytes] = {}
    active = False
    with path.open("r", encoding="ascii") as f:
        for raw in f:
            line = raw.strip()
            if line.startswith("Count = "):
                active = line == wanted
                if not active and fields:
                    break
                continue
            if not active or " = " not in line:
                continue
            key, value = line.split(" = ", 1)
            if key in {"Seed", "PK", "SK", "M", "Sn"}:
                fields[key] = bytes.fromhex(value)
    return fields


def words(raw: bytes) -> list[int]:
    if len(raw) % 2:
        raise ValueError("odd byte count")
    return [raw[i] | (raw[i + 1] << 8) for i in range(0, len(raw), 2)]


def inv(a: int) -> int:
    return pow(a % Q, Q - 2, Q)


def mat_inv(a: list[list[int]]) -> list[list[int]]:
    n = len(a)
    aug = [row[:] + [1 if i == j else 0 for j in range(n)] for i, row in enumerate(a)]
    for col in range(n):
        piv = next((r for r in range(col, n) if aug[r][col] % Q), None)
        if piv is None:
            raise ValueError("singular matrix")
        aug[col], aug[piv] = aug[piv], aug[col]
        scale = inv(aug[col][col])
        aug[col] = [(x * scale) % Q for x in aug[col]]
        for r in range(n):
            if r == col or aug[r][col] % Q == 0:
                continue
            scale = aug[r][col]
            aug[r] = [(x - scale * y) % Q for x, y in zip(aug[r], aug[col])]
    return [row[n:] for row in aug]


def mat_rank(a: list[list[int]]) -> int:
    if not a:
        return 0
    rows = [row[:] for row in a]
    rank = 0
    cols = len(rows[0])
    for col in range(cols):
        piv = next((r for r in range(rank, len(rows)) if rows[r][col] % Q), None)
        if piv is None:
            continue
        rows[rank], rows[piv] = rows[piv], rows[rank]
        scale = inv(rows[rank][col])
        rows[rank] = [(x * scale) % Q for x in rows[rank]]
        for r in range(len(rows)):
            if r == rank or rows[r][col] % Q == 0:
                continue
            scale = rows[r][col]
            rows[r] = [(x - scale * y) % Q for x, y in zip(rows[r], rows[rank])]
        rank += 1
        if rank == len(rows):
            break
    return rank


def kernel_basis(a: list[list[int]]) -> list[list[int]]:
    rows = [row[:] for row in a]
    m = len(rows)
    n = len(rows[0])
    pivot_cols: list[int] = []
    rank = 0
    for col in range(n):
        piv = next((r for r in range(rank, m) if rows[r][col] % Q), None)
        if piv is None:
            continue
        rows[rank], rows[piv] = rows[piv], rows[rank]
        scale = inv(rows[rank][col])
        rows[rank] = [(x * scale) % Q for x in rows[rank]]
        for r in range(m):
            if r == rank or rows[r][col] % Q == 0:
                continue
            scale = rows[r][col]
            rows[r] = [(x - scale * y) % Q for x, y in zip(rows[r], rows[rank])]
        pivot_cols.append(col)
        rank += 1
    free = [j for j in range(n) if j not in pivot_cols]
    basis: list[list[int]] = []
    for f in free:
        vec = [0] * n
        vec[f] = 1
        for r, p in reversed(list(enumerate(pivot_cols))):
            vec[p] = (-rows[r][f]) % Q
        basis.append(vec)
    return basis


def mat_vec(a: list[list[int]], x: list[int], *, rows: int, cols: int) -> list[int]:
    return [sum(a[i * cols + j] * x[j] for j in range(cols)) % Q for i in range(rows)]


def cubic_monomials(z: list[int]) -> list[int]:
    out = [0] * ((R + 2) * (R + 1) * R // 6)
    q = 0
    for i in range(R):
        for j in range(i, R):
            zij = z[i] * z[j] % Q
            for k in range(j, R):
                out[q] = zij * z[k] % Q
                q += 1
    return out


def eval_public(pk: list[int], z: list[int]) -> list[int]:
    mono = cubic_monomials(z)
    terms = len(mono)
    return [
        sum(pk[i * terms + j] * mono[j] for j in range(terms)) % Q
        for i in range(M)
    ]


def jacobian(pk: list[int], z: list[int]) -> list[list[int]]:
    derivative_monomials: list[list[int]] = []
    for i, j, k in TRIPLES:
        values = []
        for col in range(R):
            value = 0
            if col == i:
                value += z[j] * z[k]
            if col == j:
                value += z[i] * z[k]
            if col == k:
                value += z[i] * z[j]
            values.append(value % Q)
        derivative_monomials.append(values)

    return [
        [
            sum(pk[row * len(TRIPLES) + t] * derivative_monomials[t][col] for t in range(len(TRIPLES)))
            % Q
            for col in range(R)
        ]
        for row in range(M)
    ]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--kat",
        type=Path,
        default=Path(
            "source/facto-dsa/Implementations and Test_Vectors/Test_Vectors/"
            "KAT_SIG_Facto-DSA-128.txt"
        ),
    )
    ap.add_argument("--count", type=int, default=0)
    ap.add_argument("--samples", type=int, default=5)
    args = ap.parse_args()

    f = parse_kat(args.kat, args.count)
    pk = words(f["PK"])
    sk = words(f["SK"])
    print("pk_sha256", hashlib.sha256(f["PK"]).hexdigest())
    print("sk_sha256", hashlib.sha256(f["SK"]).hexdigest())
    print("pk_words", len(pk), "sk_words", len(sk))

    sinv = [
        sk[SK_SINV_OFFSET + i * R : SK_SINV_OFFSET + (i + 1) * R]
        for i in range(R)
    ]
    s = mat_inv(sinv)
    l2 = s[N:2 * N]
    print("rank_S", mat_rank(s), "rank_L2", mat_rank(l2))

    k2 = kernel_basis(l2)
    print("dim_K2", len(k2))

    rng = random.Random(0xFAC7028)
    for label in ("K2", "outside"):
        for sample in range(args.samples):
            if label == "K2":
                coeff = [rng.randrange(Q) for _ in k2]
                v = [
                    sum(coeff[t] * k2[t][j] for t in range(len(k2))) % Q
                    for j in range(R)
                ]
            else:
                v = [rng.randrange(Q) for _ in range(R)]
            pv = eval_public(pk, v)
            jv = jacobian(pk, v)
            ker = kernel_basis(jv)
            print(
                f"{label}[{sample}]",
                "P_zero", all(x == 0 for x in pv),
                "rank_J", mat_rank(jv),
                "dim_ker_J", len(ker),
                "ker_eq_K2",
                mat_rank(k2 + ker) == N,
            )


if __name__ == "__main__":
    main()
