#!/usr/bin/env python3
"""Exact GF(2) rank audit of the GreatWall L1 matrices in the permitted ZIP."""

import hashlib
import re
import sys
import zipfile


ZIP_SHA256 = "814cd3b977ddc0cc59828861c145580473b1a62a66da852b078edbaf689f5a8d"
BASE = "Implementations/Reference_Implementation/GreatWall128f/"
PROFILES = ((128, 137), (192, 197), (256, 263), (512, 521))


def matrix_words(source: str, name: str, n: int) -> list[int]:
    match = re.search(
        r"const uint64_t " + re.escape(name) + r"\s*\[\d+\]\[\d+\]\s*=\s*\{(.*?)\n\};",
        source,
        re.S,
    )
    if match is None:
        raise ValueError(f"missing matrix {name}")
    result = []
    for row in re.findall(r"\{([^}]*)\}", match.group(1)):
        words = [int(word, 16) for word in re.findall(r"0x([0-9a-f]+)", row)]
        value = sum(word << (64 * i) for i, word in enumerate(words))
        result.append(value & ((1 << n) - 1))
    if len(result) != n:
        raise ValueError(f"{name}: expected {n} rows, found {len(result)}")
    return result


def kernel_basis(rows: list[int], n: int) -> tuple[int, list[int]]:
    """Return rank and a basis for the right kernel using [rows | identity]."""
    work = [rows[i] | (1 << (n + i)) for i in range(n)]
    pivot_columns = []
    rank = 0
    for column in range(n):
        pivot = next(
            (i for i in range(rank, n) if (work[i] >> column) & 1), None
        )
        if pivot is None:
            continue
        work[rank], work[pivot] = work[pivot], work[rank]
        for i in range(n):
            if i != rank and ((work[i] >> column) & 1):
                work[i] ^= work[rank]
        pivot_columns.append(column)
        rank += 1

    pivot_set = set(pivot_columns)
    basis = []
    for free in range(n):
        if free in pivot_set:
            continue
        vector = 1 << free
        for i, pivot_column in enumerate(pivot_columns):
            if (work[i] >> free) & 1:
                vector |= 1 << pivot_column
        basis.append(vector)
    return rank, basis


def main() -> None:
    path = sys.argv[1] if len(sys.argv) > 1 else "GreatWall.zip"
    with open(path, "rb") as handle:
        digest = hashlib.sha256(handle.read()).hexdigest()
    print(f"zip_sha256={digest}")
    if digest != ZIP_SHA256:
        raise SystemExit("ZIP hash does not match the authorized submission")

    with zipfile.ZipFile(path) as archive:
        for security, n in PROFILES:
            member = f"{BASE}greatwall-{security}-matrix.c"
            source = archive.read(member).decode("utf-8")
            l1 = matrix_words(source, f"greatwall_mat_{n}_1", n)
            identity = sum(1 << i for i in range(n))
            plus_i = [value ^ ((identity >> i) & 1) for i, value in enumerate(l1)]
            rank_l1, kernel_l1 = kernel_basis(l1, n)
            rank_plus_i, kernel_plus_i = kernel_basis(plus_i, n)
            print(
                f"n={n} rank(L1)={rank_l1} nullity(L1)={len(kernel_l1)} "
                f"rank(L1+I)={rank_plus_i} nullity(L1+I)={len(kernel_plus_i)}"
            )
            for index, vector in enumerate(kernel_plus_i, 1):
                print(f"  ker(L1+I)[{index}]={vector:0{(n + 3) // 4}x}")


if __name__ == "__main__":
    main()
