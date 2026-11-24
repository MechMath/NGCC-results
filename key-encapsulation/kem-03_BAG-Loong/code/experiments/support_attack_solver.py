#!/usr/bin/env python3
import json
import resource
import sys
import time


def parse_export(path):
    lines = open(path, encoding="ascii").read().splitlines()
    meta = dict(item.split("=", 1) for item in lines[0].split()[1:])
    n, n1, m = (int(meta[key]) for key in ("n", "n1", "m"))

    def values(line):
        return [int(item, 16) for item in line.split()[1:]]

    truth = values(lines[3]) if len(lines) > 3 else None
    return n, n1, m, meta, values(lines[1]), values(lines[2]), truth


def mul_x(h, shift, m):
    terms = {
        47: (5, 0),
        67: (5, 2, 1, 0),
        83: (7, 4, 2, 0),
        97: (6, 0),
    }[m]
    value = h << shift
    for degree in range(value.bit_length() - 1, m - 1, -1):
        if (value >> degree) & 1:
            value ^= 1 << degree
            for term in terms:
                value ^= 1 << (degree - m + term)
    return value


def solve(n, n1, m, meta, h, s):
    rank_x = int(meta["axy00"])
    rank_y = int(meta["axy11"])
    intersection = int(meta["axy01"])
    y_support = tuple(
        list(range(intersection))
        + list(range(rank_x, rank_x + rank_y - intersection))
    )
    per_matrix = n * n1
    unknowns = per_matrix * (rank_x + rank_y)
    mask = (1 << unknowns) - 1
    rhs_bit = unknowns
    pivots = {}
    matrix_mul = [[mul_x(hv, a, m) for a in range(rank_x)] for hv in h]
    started = time.time()

    equation_count = 0
    for i in range(n):
        for j in range(n1):
            q = i * n1 + j
            for b in range(m):
                row = 0
                for k in range(n):
                    columns = matrix_mul[i * n + k]
                    base = (k * n1 + j) * rank_x
                    for a, product in enumerate(columns):
                        if (product >> b) & 1:
                            row |= 1 << (base + a)
                if b in y_support:
                    row |= 1 << (
                        per_matrix * rank_x + q * rank_y + y_support.index(b)
                    )
                row |= ((s[q] >> b) & 1) << rhs_bit
                equation_count += 1

                while row & mask:
                    pivot = (row & mask).bit_length() - 1
                    old = pivots.get(pivot)
                    if old is None:
                        pivots[pivot] = row
                        break
                    row ^= old
                if not (row & mask) and ((row >> rhs_bit) & 1):
                    raise RuntimeError("inconsistent linear system")

    if len(pivots) != unknowns:
        raise RuntimeError(f"rank {len(pivots)} != {unknowns}")

    solution = 0
    for pivot in range(unknowns):
        row = pivots[pivot]
        known = row & mask
        known ^= 1 << pivot
        rhs = (row >> rhs_bit) & 1
        if (known & solution).bit_count() & 1:
            rhs ^= 1
        if rhs:
            solution |= 1 << pivot

    x_recovered = []
    for q in range(per_matrix):
        value = 0
        for a in range(rank_x):
            value |= ((solution >> (q * rank_x + a)) & 1) << a
        x_recovered.append(value)
    return x_recovered, {
        "equations": equation_count,
        "unknowns": unknowns,
        "rank": len(pivots),
        "forward_and_solve_seconds": round(time.time() - started, 3),
        "process_maxrss_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
    }


def main():
    n, n1, m, meta, h, s, truth = parse_export(sys.argv[1])
    recovered, stats = solve(n, n1, m, meta, h, s)
    stats["parameter_set"] = sys.argv[3] if len(sys.argv) > 3 else "unknown"
    stats["secret_vector_elements"] = len(recovered)
    if truth is not None:
        stats["recovered_exactly"] = recovered == truth
        stats["truth_max_support_value"] = max(truth)
    print(json.dumps(stats, indent=2, sort_keys=True))
    if len(sys.argv) > 2:
        packed = bytearray((len(recovered) * m + 7) // 8)
        for index, value in enumerate(recovered):
            for bit in range(m):
                if (value >> bit) & 1:
                    position = index * m + bit
                    packed[position // 8] |= 1 << (7 - position % 8)
        with open(sys.argv[2], "wb") as handle:
            handle.write(packed)
    if truth is not None and recovered != truth:
        mismatches = [i for i, (a, b) in enumerate(zip(recovered, truth)) if a != b]
        print("mismatches", mismatches[:20], file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
