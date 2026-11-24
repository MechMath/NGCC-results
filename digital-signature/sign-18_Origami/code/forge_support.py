#!/usr/bin/env python3
"""Forge an Origami-128 signature from public support-pattern leakage.

Inputs are the public map dump produced by the submitted reference code
(`map.txt`) plus a message and a signature carrying the salt to target.
The script does not read the secret key.  It recovers the zone oil spaces
from forbidden monomial pairs and solves the exposed linear layers.
"""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path


N = 200
M = 104
BLOCKS = ((0, 32), (32, 64), (64, 96), (96, 104))
OIL_COUNTS = (40, 40, 40, 8)


def gf_mul(a: int, b: int) -> int:
    out = 0
    for _ in range(4):
        if b & 1:
            out ^= a
        b >>= 1
        a <<= 1
        if a & 0x10:
            a ^= 0x13
    return out & 0xF


def gf_inv(a: int) -> int:
    if a == 0:
        raise ZeroDivisionError("inverse of zero")
    for b in range(1, 16):
        if gf_mul(a, b) == 1:
            return b
    raise AssertionError("GF(16) inverse not found")


def solve_linear(a: list[list[int]], rhs: list[int]) -> list[int]:
    rows = len(a)
    cols = len(a[0])
    aug = [row[:] + [rhs[i]] for i, row in enumerate(a)]
    pivot_row = 0
    pivot_cols: list[int] = []
    for col in range(cols):
        pivot = next((r for r in range(pivot_row, rows) if aug[r][col]), None)
        if pivot is None:
            continue
        aug[pivot_row], aug[pivot] = aug[pivot], aug[pivot_row]
        inv = gf_inv(aug[pivot_row][col])
        aug[pivot_row] = [gf_mul(inv, value) for value in aug[pivot_row]]
        for r in range(rows):
            if r == pivot_row or aug[r][col] == 0:
                continue
            factor = aug[r][col]
            aug[r] = [x ^ gf_mul(factor, y) for x, y in zip(aug[r], aug[pivot_row])]
        pivot_cols.append(col)
        pivot_row += 1
        if pivot_row == rows:
            break
    for row in aug:
        if not any(row[:-1]) and row[-1]:
            raise ValueError("inconsistent linear system")
    if len(pivot_cols) != rows:
        raise ValueError(f"rank {len(pivot_cols)} < {rows}")
    out = [0] * cols
    for r, col in enumerate(pivot_cols):
        out[col] = aug[r][-1]
    return out


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--map", default="map.txt")
    parser.add_argument("--signature", default="sig.bin")
    parser.add_argument("--message", default="msg.bin")
    parser.add_argument("--out", default="forged_sig.bin")
    parser.add_argument("--summary", default="forge_summary.txt")
    args = parser.parse_args()

    map_path = Path(args.map)
    terms: list[list[tuple[int, int, int]]] = [[] for _ in range(M)]
    with map_path.open() as stream:
        header = stream.readline().split()
        if header[0] != "P":
            raise ValueError("bad map permutation header")
        secret_to_public = [int(value) for value in header[1:]]
        target_header = stream.readline().split()
        if target_header[0] != "T":
            raise ValueError("bad target header")
        target = [int(value) for value in target_header[1:]]
        for line in stream:
            marker, eq, a, b, coeff = line.split()
            if marker != "C":
                raise ValueError("bad coefficient row")
            terms[int(eq)].append((int(a), int(b), int(coeff)))

    salt = Path(args.signature).read_bytes()[-16:]
    message = Path(args.message).read_bytes()
    seed_material = hashlib.shake_256(b"public-support-prototype" + message + salt).digest(N // 2)
    x = [0] * N
    for i in range(N):
        x[i] = seed_material[i // 2] >> (4 * (i & 1)) & 0xF

    prefix: set[int] = set()
    recovered: list[list[int]] = []
    for block, oil_count in zip(BLOCKS, OIL_COUNTS):
        active = {
            value
            for eq in range(*block)
            for a, b, _ in terms[eq]
            for value in (a, b)
        }
        new = active - prefix
        if len(new) not in (64, 8):
            raise ValueError(f"unexpected new-variable count {len(new)}")
        adjacency = {value: set() for value in new}
        for eq in range(*block):
            for a, b, _ in terms[eq]:
                if a in new and b in new:
                    adjacency[a].add(b)
                    adjacency[b].add(a)
        # Public parameters fix the oil dimension of each zone.
        if oil_count == 8:
            oil = sorted(new)
        else:
            color: dict[int, int] = {}
            start = min(new)
            color[start] = 0
            stack = [start]
            while stack:
                value = stack.pop()
                for other in adjacency[value]:
                    wanted = 1 - color[value]
                    if other in color:
                        if color[other] != wanted:
                            raise ValueError("current-zone support graph is not bipartite")
                    else:
                        color[other] = wanted
                        stack.append(other)
            if len(color) != len(new):
                raise ValueError("current-zone support graph is disconnected")
            side0 = {value for value, part in color.items() if part == 0}
            side1 = new - side0
            oil = sorted(side0 if len(side0) == oil_count else side1)
            if len(oil) != oil_count:
                raise ValueError("could not identify expected oil side")
        vinegar = sorted(new - set(oil))
        solution = None
        for attempt in range(64):
            if attempt:
                retry = hashlib.shake_256(
                    seed_material + bytes((BLOCKS.index((block[0], block[1])), attempt))
                ).digest(64)
                for j, value in enumerate(vinegar):
                    x[value] = retry[j // 2] >> (4 * (j & 1)) & 0xF
            matrix: list[list[int]] = []
            rhs: list[int] = []
            for eq in range(*block):
                row = [0] * oil_count
                for a, b, _ in terms[eq]:
                    if a not in oil and b not in oil:
                        raise ValueError(f"unexpected same-layer term in equation {eq}")
                for j, value in enumerate(oil):
                    value_coeff = 0
                    for a, b, coeff in terms[eq]:
                        if a == value:
                            value_coeff ^= gf_mul(coeff, x[b])
                        elif b == value:
                            value_coeff ^= gf_mul(coeff, x[a])
                    row[j] = value_coeff
                matrix.append(row)
                rhs.append(target[eq])
            try:
                solution = solve_linear(matrix, rhs)
                break
            except ValueError:
                continue
        if solution is None:
            raise RuntimeError("no full-rank local system after 64 attempts")
        for value, result in zip(oil, solution):
            x[value] = result
        prefix |= active
        recovered.append(oil)

    public = [0] * N
    for secret, public_index in enumerate(secret_to_public):
        public[public_index] = x[secret]
    signature = bytearray(100)
    for i, value in enumerate(public):
        signature[i // 2] |= value << (4 * (i & 1))
    signature += salt
    Path(args.out).write_bytes(signature)

    summary = [
        "public-support attack prototype",
        f"message_sha256={hashlib.sha256(message).hexdigest()}",
        f"salt={salt.hex()}",
        f"public_signature={signature[:-16].hex()}",
        "recovered_oil_sets=" + ";".join(",".join(map(str, oil)) for oil in recovered),
    ]
    Path(args.summary).write_text("\n".join(summary) + "\n")
    print("\n".join(summary))


if __name__ == "__main__":
    main()
