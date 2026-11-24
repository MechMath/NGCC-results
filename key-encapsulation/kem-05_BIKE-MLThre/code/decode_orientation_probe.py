#!/usr/bin/env python3
"""Exact deterministic replay of the BIKE-MLThre reference BGF feature loop.

This probe keeps the supported 128-bit dimensions (r=12323, DV=71) and compares
valid key-pair rotations on the same attacker-chosen dense c0.  It computes the
decoder's integer threshold statistics, not cycle timing.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
from dataclasses import dataclass, asdict

import numpy as np

R = 12323
DV = 71
TAU = 3
NITER = 5
MASK = (1 << R) - 1


def rot(x: int, a: int) -> int:
    a %= R
    return ((x << a) | (x >> (R - a))) & MASK if a else x


def bits_positions(x: int) -> list[int]:
    out: list[int] = []
    while x:
        low = x & -x
        out.append(low.bit_length() - 1)
        x ^= low
    return out


def poly_from_positions(pos: list[int]) -> int:
    z = 0
    for p in pos:
        z ^= 1 << p
    return z


def convolve_sparse(c: int, support: list[int]) -> int:
    z = 0
    for s in support:
        z ^= rot(c, s)
    return z


def base_threshold(weight: int) -> int:
    # BIKE_MLTHRE 128 reference fallback/initial threshold curve.
    return max(36, int(13.530 + 0.0069722 * weight))


def collect(s: int, support: list[int], t: int) -> tuple[int, int, tuple[int, ...]]:
    bits = np.fromiter(((s >> i) & 1 for i in range(R)), dtype=np.uint16, count=R)
    ctr = np.zeros(R, dtype=np.uint16)
    for p in support:
        ctr += np.roll(bits, -p)
    hist, _ = np.histogram(ctr, bins=np.arange(t - 2.5, t + 3.5, 1))
    black = int(np.count_nonzero(ctr >= t))
    gray_t = max(0, t - TAU)
    gray = int(np.count_nonzero((ctr >= gray_t) & (ctr < t)))
    return black, gray, tuple(int(x) for x in hist)


def select(s: int, support: list[int], t: int) -> tuple[list[int], int, int]:
    bits = np.fromiter(((s >> i) & 1 for i in range(R)), dtype=np.uint16, count=R)
    ctr = np.zeros(R, dtype=np.uint16)
    for p in support:
        ctr += np.roll(bits, -p)
    flips = np.flatnonzero(ctr >= t).tolist()
    gray_t = max(0, t - TAU)
    black_n = len(flips)
    gray_n = int(np.count_nonzero((ctr >= gray_t) & (ctr < t)))
    return flips, black_n, gray_n


def apply_flips(s: int, support: list[int], flips: list[int]) -> int:
    support_poly = poly_from_positions(support)
    for j in flips:
        s ^= rot(support_poly, j)
    return s


@dataclass(frozen=True)
class Trace:
    initial_weight: int
    weights: list[int]
    black: list[int]
    gray: list[int]
    histograms: list[list[int]]
    flips: list[int]
    success: bool


def trace(c: int, h0: list[int], h1: list[int]) -> Trace:
    s = convolve_sparse(c, h0)
    initial = s.bit_count()
    prev = s
    weights: list[int] = []
    black: list[int] = []
    gray: list[int] = []
    histograms: list[list[int]] = []
    flips: list[int] = []
    for _ in range(NITER):
        w = s.bit_count()
        weights.append(w)
        t = base_threshold(w)
        b, g, hist = collect(s, h0, t)
        black.append(b)
        gray.append(g)
        histograms.append(list(hist))
        # BFIter selects both halves from the same syndrome, then applies all
        # selected row XORs after selection.
        f0, b0, g0 = select(s, h0, t)
        f1, b1, g1 = select(s, h1, t)
        black[-1] += b1
        gray[-1] += g1
        flips.append(len(f0) + len(f1))
        s = apply_flips(s, h0, f0)
        s = apply_flips(s, h1, f1)
        prev = s
    return Trace(initial, weights, black, gray, histograms, flips, s == 0)


def sparse_support(rng: random.Random, weight: int) -> list[int]:
    return sorted(rng.sample(range(R), weight))


def gf2_divmod(a: int, b: int) -> tuple[int, int]:
    q = 0
    db = b.bit_length() - 1
    while a and a.bit_length() - 1 >= db:
        shift = a.bit_length() - 1 - db
        q ^= 1 << shift
        a ^= b << shift
    return q, a


def gf2_gcd_ext(a: int, b: int, modulus: int) -> tuple[int, int, int]:
    # x*a + y*b = g over GF(2), without reducing intermediate products.
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1
    while r:
        q, rem = gf2_divmod(old_r, r)
        old_r, r = r, rem
        old_s, s = s, old_s ^ gf2_mul(q, s)
        old_t, t = t, old_t ^ gf2_mul(q, t)
    return old_r, old_s, old_t


def gf2_mul(a: int, b: int) -> int:
    z = 0
    while b:
        if b & 1:
            z ^= a
        b >>= 1
        a <<= 1
    return z


def gf2_inverse_cyclic(a: int) -> int:
    modulus = (1 << R) | 1
    g, s, _ = gf2_gcd_ext(a, modulus, modulus)
    if g != 1:
        raise ValueError("not invertible")
    # Reduce s modulo x^r+1.
    q, rem = gf2_divmod(s, modulus)
    return rem


def fingerprint(obj: object) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True).encode()).hexdigest()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=0x4D4C54485245)
    ap.add_argument("--density", type=int, default=4000)
    ap.add_argument("--rotations", type=int, default=8)
    args = ap.parse_args()

    rng = random.Random(args.seed)
    h0 = sparse_support(rng, DV)
    h1 = sparse_support(rng, DV)
    h0_poly = poly_from_positions(h0)
    h1_poly = poly_from_positions(h1)
    public_h = convolve_sparse(gf2_inverse_cyclic(h0_poly), h1)
    e0 = sparse_support(rng, 67)
    e1 = sparse_support(rng, 67)
    e1h = convolve_sparse(poly_from_positions(e1), bits_positions(public_h))
    c = poly_from_positions(e0) ^ e1h
    rows = []
    for a in range(args.rotations):
        h0a = sorted((p + a) % R for p in h0)
        h1a = sorted((p + a) % R for p in h1)
        tr = trace(c, h0a, h1a)
        row = {"rotation": a, "trace": asdict(tr)}
        row["trace_hash"] = fingerprint(row["trace"])
        rows.append(row)

    result = {
        "parameters": {"r": R, "DV": DV, "tau": TAU, "iterations": NITER},
        "seed": args.seed,
        "c0_density": args.density,
        "h0": h0,
        "h1": h1,
        "c0_weight": c.bit_count(),
        "public_h_weight": public_h.bit_count(),
        "rows": rows,
        "distinct_trace_hashes": len({r["trace_hash"] for r in rows}),
        "distinct_after_first_iteration": len(
            {fingerprint({k: v for k, v in r["trace"].items() if k not in ("initial_weight", "weights")}) for r in rows}
        ),
    }
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
