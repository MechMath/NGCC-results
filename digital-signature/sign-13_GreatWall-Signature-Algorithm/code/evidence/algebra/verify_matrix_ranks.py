#!/usr/bin/env python3
"""Read the permitted GreatWall ZIP and compute GF(2) ranks of its Pylon maps."""

import argparse
import re
import zipfile


PARAMETERS = [
    (137, 70, 75, "greatwall-128-matrix.c"),
    (197, 94, 105, "greatwall-192-matrix.c"),
    (263, 129, 136, "greatwall-256-matrix.c"),
    (521, 248, 273, "greatwall-512-matrix.c"),
]


def gf2_rank(rows, width):
    rows = [row & ((1 << width) - 1) for row in rows]
    rank = 0
    for column in range(width):
        pivot = next(
            (i for i in range(rank, len(rows)) if (rows[i] >> column) & 1),
            None,
        )
        if pivot is None:
            continue
        rows[rank], rows[pivot] = rows[pivot], rows[rank]
        for i in range(len(rows)):
            if i != rank and ((rows[i] >> column) & 1):
                rows[i] ^= rows[rank]
        rank += 1
    return rank


def matrix_rows(source, name):
    match = re.search(
        r"const\s+uint64_t\s+"
        + re.escape(name)
        + r"\s*\[[^\]]+\][^=]*=\s*\{",
        source,
    )
    if match is None:
        raise ValueError(f"matrix not found: {name}")

    depth = 1
    start = match.end()
    end = start
    while depth:
        if source[end] == "{":
            depth += 1
        elif source[end] == "}":
            depth -= 1
        end += 1

    rows = []
    for line in source[start : end - 1].splitlines():
        words = re.findall(r"0x[0-9a-fA-F]+", line)
        if words:
            rows.append(sum(int(word, 16) << (64 * i) for i, word in enumerate(words)))
    return rows


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("zip_path")
    args = parser.parse_args()

    with zipfile.ZipFile(args.zip_path) as archive:
        for n, e1, e2, filename in PARAMETERS:
            member = (
                "Implementations/Reference_Implementation/GreatWall128s/" + filename
            )
            source = archive.read(member).decode("utf-8")
            names = [
                f"greatwall_mat_{n}_0",
                f"greatwall_mat_{n}_1",
                f"greatwall_mat_{n}_2",
                f"greatwall_mat_{n}_2_inv",
                f"greatwall_pow_mat_{n}_{e1}",
                f"greatwall_pow_mat_{n}_{e2}",
            ]
            for name in names:
                rows = matrix_rows(source, name)
                assert len(rows) == n
                print(f"n={n} {name} rank={gf2_rank(rows, n)}/{n}")

            matrix1 = matrix_rows(source, f"greatwall_mat_{n}_1")
            matrix1_plus_identity = [
                matrix1[i] ^ (1 << i) for i in range(n)
            ]
            rank = gf2_rank(matrix1_plus_identity, n)
            print(f"n={n} M1+I rank={rank}/{n}")


if __name__ == "__main__":
    main()
