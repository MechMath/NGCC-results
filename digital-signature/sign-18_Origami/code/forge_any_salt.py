#!/usr/bin/env python3
"""Construct an Origami signature from the public verification map.

The script uses only:
  * the public key and public reference map dump;
  * a chosen message;
  * the original public hash-to-field routine; and
  * the original reference verifier for independent acceptance.

The map coefficients reveal a triangular decomposition.  Given any target,
the main-zone systems are linear after their vinegar coordinates are chosen.
The rank of the final tail matrix can depend on those earlier choices, so the
script repeats the public random choice if the affine target falls outside a
rank-deficient tail image.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import resource
import subprocess
import sys
import time


PROFILES = {
    128: {
        "n": 200,
        "m": 104,
        "main_zones": 3,
        "main_v": 24,
        "main_o": 40,
        "main_m": 32,
        "tail_o": 8,
        "tail_m": 8,
        "salt_bytes": 16,
    },
    256: {
        "n": 968,
        "m": 488,
        "main_zones": 6,
        "main_v": 60,
        "main_o": 100,
        "main_m": 80,
        "tail_o": 8,
        "tail_m": 8,
        "salt_bytes": 32,
    },
}

PATH_MUL = (1, 2, 4, 8, 3, 6, 12, 11, 5, 10, 7, 14, 15, 13, 9)
MUL = [[0] * 16 for _ in range(16)]
for _i in range(15):
    for _j in range(15):
        MUL[PATH_MUL[_i]][PATH_MUL[_j]] = PATH_MUL[(_i + _j) % 15]


def gf_mul(a: int, b: int) -> int:
    return MUL[a][b]


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
            aug[r] = [
                x ^ gf_mul(factor, y) for x, y in zip(aug[r], aug[pivot_row])
            ]
        pivot_cols.append(col)
        pivot_row += 1
        if pivot_row == rows:
            break
    for row in aug:
        if not any(row[:-1]) and row[-1]:
            raise ValueError("target is outside this affine local image")
    if len(pivot_cols) != rows:
        raise ValueError(f"local rank {len(pivot_cols)} is below {rows}")
    out = [0] * cols
    for r, col in enumerate(pivot_cols):
        out[col] = aug[r][-1]
    return out


def load_map(
    path: Path,
) -> tuple[int, int, list[int], list[list[tuple[int, int, int]]]]:
    with path.open() as stream:
        first = stream.readline().split()
        if first[0] != "P":
            raise ValueError("bad public permutation header")
        permutation = [int(value) for value in first[1:]]
        second = stream.readline().split()
        if second[0] != "T":
            raise ValueError("bad map target header")
        n = len(permutation)
        m = len(second) - 1
        terms: list[list[tuple[int, int, int]]] = [[] for _ in range(m)]
        for line in stream:
            marker, eq, a, b, coeff = line.split()
            if marker != "C":
                raise ValueError("bad map coefficient row")
            terms[int(eq)].append((int(a), int(b), int(coeff)))
    return n, m, permutation, terms


def recover_support(
    terms: list[list[tuple[int, int, int]]],
    blocks: list[tuple[int, int]],
    oil_counts: list[int],
) -> list[tuple[set[int], list[int], list[int]]]:
    prefix: set[int] = set()
    zones: list[tuple[set[int], list[int], list[int]]] = []
    main_active_size = None
    for block, oil_count in zip(blocks, oil_counts):
        active = {
            value
            for eq in range(*block)
            for a, b, _ in terms[eq]
            for value in (a, b)
        }
        new = active - prefix
        if oil_count == len(new):
            oil = sorted(new)
        else:
            if main_active_size is None:
                main_active_size = len(new)
            elif len(new) != main_active_size:
                raise ValueError(f"unexpected zone size {len(new)}")
            adjacency = {value: set() for value in new}
            for eq in range(*block):
                for a, b, _ in terms[eq]:
                    if a in new and b in new:
                        adjacency[a].add(b)
                        adjacency[b].add(a)
            color: dict[int, int] = {}
            for start in sorted(new):
                if start in color:
                    continue
                color[start] = 0
                stack = [start]
                while stack:
                    value = stack.pop()
                    for other in adjacency[value]:
                        wanted = 1 - color[value]
                        if other in color:
                            if color[other] != wanted:
                                raise ValueError("support graph is not bipartite")
                        else:
                            color[other] = wanted
                            stack.append(other)
            side0 = {value for value, part in color.items() if part == 0}
            side1 = new - side0
            if len(side0) == oil_count:
                oil = sorted(side0)
            elif len(side1) == oil_count:
                oil = sorted(side1)
            else:
                raise ValueError("cannot identify the public oil support")
        vinegar = sorted(new - set(oil))
        zones.append((active, oil, vinegar))
        prefix |= active
    return zones


def target_for(
    hash_target: Path,
    message: Path,
    salt: bytes,
    scratch: Path,
    expected_m: int,
    command_mode: str | None,
) -> list[int]:
    salt_path = scratch / "candidate-salt.bin"
    salt_path.write_bytes(salt)
    command = [str(hash_target)]
    if command_mode:
        command.append(command_mode)
    command.extend((str(message), str(salt_path)))
    text = subprocess.check_output(command, text=True)
    fields = text.split()
    if len(fields) != expected_m + 1 or fields[0] != "T":
        raise ValueError("bad hash-target output")
    return [int(value) for value in fields[1:]]


def solve_target(
    n: int,
    terms: list[list[tuple[int, int, int]]],
    zones: list[tuple[set[int], list[int], list[int]]],
    target: list[int],
    seed_material: bytes,
    max_vinegar_attempts: int,
    blocks: list[tuple[int, int]],
) -> list[int]:
    x = [0] * n
    for i in range(n):
        x[i] = seed_material[i // 2] >> (4 * (i & 1)) & 0xF
    for zone_index, (_, oil, vinegar) in enumerate(zones):
        block = blocks[zone_index]
        solved = False
        for attempt in range(max_vinegar_attempts):
            if attempt:
                retry = hashlib.shake_256(
                    seed_material + bytes((zone_index, attempt))
                ).digest((len(vinegar) + 1) // 2)
                for j, value in enumerate(vinegar):
                    x[value] = retry[j // 2] >> (4 * (j & 1)) & 0xF
            matrix: list[list[int]] = []
            rhs: list[int] = []
            for eq in range(*block):
                row: list[int] = []
                for value in oil:
                    coefficient = 0
                    for a, b, coeff in terms[eq]:
                        if a == value:
                            coefficient ^= gf_mul(coeff, x[b])
                        elif b == value:
                            coefficient ^= gf_mul(coeff, x[a])
                    row.append(coefficient)
                matrix.append(row)
                rhs.append(target[eq])
            try:
                solution = solve_linear(matrix, rhs)
            except ValueError:
                continue
            for value, result in zip(oil, solution):
                x[value] = result
            solved = True
            break
        if not solved:
            raise ValueError(f"zone {zone_index} target rejected")
    return x


def evaluate(
    terms: list[list[tuple[int, int, int]]], values: list[int]
) -> list[int]:
    output: list[int] = []
    for equation in terms:
        total = 0
        for a, b, coefficient in equation:
            total ^= gf_mul(coefficient, gf_mul(values[a], values[b]))
        output.append(total)
    return output


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--map", type=Path, required=True)
    parser.add_argument("--pk", type=Path, required=True)
    parser.add_argument("--message", type=Path, required=True)
    parser.add_argument("--hash-target", type=Path, required=True)
    parser.add_argument("--verifier", type=Path, required=True)
    parser.add_argument("--hash-command-mode")
    parser.add_argument("--verifier-command-mode")
    parser.add_argument("--security-bits", type=int, choices=sorted(PROFILES), default=128)
    parser.add_argument("--out-dir", type=Path, default=Path("fresh-forgery"))
    parser.add_argument("--max-salts", type=int, default=256)
    parser.add_argument("--max-vinegar-attempts", type=int, default=16)
    parser.add_argument("--max-prefix-attempts", type=int, default=32)
    args = parser.parse_args()

    started = time.monotonic()
    profile = PROFILES[args.security_bits]
    n, m, permutation, terms = load_map(args.map)
    if (n, m) != (profile["n"], profile["m"]):
        raise ValueError(f"map dimensions {(n, m)} do not match profile")
    blocks = [
        (zone * profile["main_m"], (zone + 1) * profile["main_m"])
        for zone in range(profile["main_zones"])
    ]
    blocks.append((m - profile["tail_m"], m))
    oil_counts = [profile["main_o"]] * profile["main_zones"] + [profile["tail_o"]]
    zones = recover_support(terms, blocks, oil_counts)
    message = args.message.read_bytes()
    args.out_dir.mkdir(parents=True, exist_ok=True)
    scratch = args.out_dir / "scratch"
    scratch.mkdir(exist_ok=True)

    attempts = []
    total_prefix_attempts = 0
    for counter in range(args.max_salts):
        salt = hashlib.shake_256(
            b"origami-public-support-salt-search" + message + counter.to_bytes(4, "big")
        ).digest(profile["salt_bytes"])
        target = target_for(
            args.hash_target,
            args.message,
            salt,
            scratch,
            m,
            args.hash_command_mode,
        )
        values = None
        target_error = None
        for prefix_attempt in range(args.max_prefix_attempts):
            total_prefix_attempts += 1
            seed_material = hashlib.shake_256(
                b"origami-public-support-vinegar"
                + message
                + salt
                + prefix_attempt.to_bytes(4, "big")
            ).digest((n + 1) // 2)
            try:
                values = solve_target(
                    n,
                    terms,
                    zones,
                    target,
                    seed_material,
                    args.max_vinegar_attempts,
                    blocks,
                )
                break
            except ValueError as exc:
                target_error = str(exc)
        if values is None:
            attempts.append(
                {
                    "counter": counter,
                    "salt": salt.hex(),
                    "error": target_error,
                    "prefix_attempts": args.max_prefix_attempts,
                }
            )
            print(f"counter={counter} rejected={target_error}", file=sys.stderr, flush=True)
            continue
        if evaluate(terms, values) != target:
            raise RuntimeError("constructed values do not evaluate to the target")

        public_values = [0] * n
        for secret_index, public_index in enumerate(permutation):
            public_values[public_index] = values[secret_index]
        packed = bytearray((n + 1) // 2)
        for i, value in enumerate(public_values):
            packed[i // 2] |= value << (4 * (i & 1))
        signature = bytes(packed) + salt
        signature_path = args.out_dir / "signature.bin"
        signature_path.write_bytes(signature)

        verify_command = [str(args.verifier)]
        if args.verifier_command_mode:
            verify_command.append(args.verifier_command_mode)
        verify_command.extend(
            (str(args.pk), str(args.message), str(signature_path))
        )
        accepted = subprocess.run(
            verify_command,
            text=True,
            capture_output=True,
        )
        report = {
            "schema": "origami-public-support-forgery/v1",
            "security_bits": args.security_bits,
            "zip_sha256": "e34f18832e968681dd0c51ce0d4b29d80e01ad29daa83dfb805718b76fdffa80",
            "public_key_sha256": hashlib.sha256(args.pk.read_bytes()).hexdigest(),
            "message_sha256": hashlib.sha256(message).hexdigest(),
            "salt": salt.hex(),
            "signature_sha256": hashlib.sha256(signature).hexdigest(),
            "map_sha256": hashlib.sha256(args.map.read_bytes()).hexdigest(),
            "salt_attempts": counter + 1,
            "prefix_attempts_total": total_prefix_attempts,
            "rejected_attempts": attempts,
            "oil_supports": [zone[1] for zone in zones],
            "verifier_exit": accepted.returncode,
            "verifier_stdout": accepted.stdout.strip(),
            "verifier_stderr": accepted.stderr.strip(),
            "elapsed_seconds": time.monotonic() - started,
            "max_rss_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
            "python": sys.version,
            "platform": {
                "sysname": os.uname().sysname,
                "nodename": os.uname().nodename,
                "release": os.uname().release,
                "version": os.uname().version,
                "machine": os.uname().machine,
            },
        }
        report_path = args.out_dir / "result.json"
        report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        if accepted.returncode != 0:
            raise SystemExit(f"reference verifier rejected candidate: {accepted.stdout}")
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0
    raise SystemExit(f"no admissible salt in {args.max_salts} attempts")


if __name__ == "__main__":
    raise SystemExit(main())
