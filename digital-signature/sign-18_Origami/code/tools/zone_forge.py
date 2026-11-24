#!/usr/bin/env python3
"""Invert the Origami-128 public map one triangular zone at a time."""

import hashlib
import pathlib
import subprocess
import sys

PATH_MUL = (1, 2, 4, 8, 3, 6, 12, 11, 5, 10, 7, 14, 15, 13, 9)
MUL = [[0] * 16 for _ in range(16)]
for _i in range(15):
    for _j in range(15):
        MUL[PATH_MUL[_i]][PATH_MUL[_j]] = PATH_MUL[(_i + _j) % 15]


def load_map(path):
    lines = pathlib.Path(path).read_text().splitlines()
    perm = [int(x) for x in lines[0].split()[1:]]
    terms = [[] for _ in range(104)]
    for line in lines[2:]:
        _, eq, a, b, coeff = line.split()
        terms[int(eq)].append((int(a), int(b), int(coeff)))
    return perm, terms


def solve_zone(terms, equations, fixed, vinegar_end):
    start = len(fixed)
    end = max(max(a, b) for eq in equations for a, b, _ in terms[eq])
    current = list(range(start, end + 1))
    assert current, (start, end)
    values = list(fixed) + [0] * len(current)
    oil_start = vinegar_end
    oils = list(range(oil_start, end + 1))
    for i in range(start, oil_start):
        values[i] = 1 + ((7 * i + 3) % 15)

    rows = []
    rhs = []
    for eq in equations:
        row = [0] * len(oils)
        constant = 0
        for a, b, coeff in terms[eq]:
            assert a <= end and b <= end, (eq, a, b, start, end)
            a_oil = a >= oil_start
            b_oil = b >= oil_start
            assert not (a_oil and b_oil), (eq, a, b)
            if a_oil or b_oil:
                oil = a if a_oil else b
                fixed_pos = b if a_oil else a
                assert 0 <= oil - oil_start < len(row), (eq, a, b, oil_start, end)
                assert 0 <= fixed_pos < len(values), (eq, a, b, len(values))
                assert 0 <= coeff < 16
                assert 0 <= values[fixed_pos] < 16, (eq, a, b, values[fixed_pos])
                row[oil - oil_start] ^= MUL[coeff][values[fixed_pos]]
            else:
                constant ^= MUL[coeff][MUL[values[a]][values[b]]]
        rows.append(row)
        rhs.append(target[eq] ^ constant)

    print(
        f"zone vars={start}..{end} equations={equations} "
        f"vinegar={start}..{oil_start - 1} oil={oil_start}..{end}",
        flush=True,
    )

    rank = 0
    pivots = []
    width = len(oils)
    for col in range(width):
        pivot = next((r for r in range(rank, len(rows)) if rows[r][col]), None)
        if pivot is None:
            continue
        rows[rank], rows[pivot] = rows[pivot], rows[rank]
        rhs[rank], rhs[pivot] = rhs[pivot], rhs[rank]
        inv = 1
        for _ in range(14):
            inv = MUL[inv][rows[rank][col]]
        rows[rank] = [MUL[inv][v] for v in rows[rank]]
        rhs[rank] = MUL[inv][rhs[rank]]
        for r in range(len(rows)):
            if r == rank or rows[r][col] == 0:
                continue
            factor = rows[r][col]
            rows[r] = [
                rows[r][c] ^ MUL[factor][rows[rank][c]] for c in range(width)
            ]
            rhs[r] ^= MUL[factor][rhs[rank]]
        pivots.append(col)
        rank += 1

    inconsistent = any(
        not any(row) and rhs[r] != 0 for r, row in enumerate(rows)
    )
    print(f"zone rank={rank} width={width} consistent={not inconsistent}", flush=True)
    if inconsistent:
        raise SystemExit(2)
    solved = [0] * width
    for r, col in enumerate(pivots):
        solved[col] = rhs[r]
    return values[start:oil_start] + solved


def evaluate(terms, values):
    out = []
    for eq_terms in terms:
        acc = 0
        for a, b, coeff in eq_terms:
            acc ^= MUL[coeff][MUL[values[a]][values[b]]]
        out.append(acc)
    return out


def main():
    if len(sys.argv) != 2:
        raise SystemExit("usage: zone_forge.py SALT_HEX")
    salt = bytes.fromhex(sys.argv[1])
    if len(salt) != 16:
        raise SystemExit("salt must be 16 bytes")

    root = pathlib.Path(".")
    (root / "fresh_salt.bin").write_bytes(salt)
    (root / "fresh_msg.bin").write_bytes((root / "msg.bin").read_bytes())
    target_line = subprocess.check_output(
        [str(root / "tools/hash_target"), str(root / "fresh_msg.bin"),
         str(root / "fresh_salt.bin")],
        text=True,
    )
    global target
    target = [int(x) for x in target_line.split()[1:]]
    print("target", " ".join(map(str, target)), flush=True)
    print("target_sha256", hashlib.sha256(bytes(target)).hexdigest(), flush=True)

    perm, terms = load_map(root / "map.txt")
    values = []
    for zone, equations in enumerate(
        (range(0, 32), range(32, 64), range(64, 96), range(96, 104))
    ):
        vinegar_end = (
            min(192, len(values) + 24) if zone < 3 else len(values)
        )
        values.extend(solve_zone(terms, equations, values, vinegar_end))
    assert len(values) == 200
    got = evaluate(terms, values)
    print("evaluation_equal", got == target, flush=True)
    if got != target:
        raise SystemExit(3)

    public = [0] * 200
    for sec_i, pub_i in enumerate(perm):
        public[pub_i] = values[sec_i]
    packed = bytearray(100)
    for i, value in enumerate(public):
        packed[i // 2] |= value << (4 * (i & 1))
    forged = bytes(packed) + salt
    (root / "forged_sig.bin").write_bytes(forged)
    print("forged_sig", forged.hex(), flush=True)

    rc = subprocess.run(
        [str(root / "tools/verify_files"), str(root / "pk.bin"),
         str(root / "fresh_msg.bin"), str(root / "forged_sig.bin")],
        text=True,
        capture_output=True,
    )
    print("reference_verify_stdout", rc.stdout.strip(), flush=True)
    print("reference_verify_exit", rc.returncode, flush=True)
    raise SystemExit(rc.returncode)


if __name__ == "__main__":
    main()
