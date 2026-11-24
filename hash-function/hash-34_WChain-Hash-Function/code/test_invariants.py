#!/usr/bin/env python3
"""Reproduce the exact component invariants stated in WChain Sections 5.2-5.3."""

from __future__ import annotations

import hashlib
import itertools
import json
import math
import time

from wchain import (
    LEFT_ROWS, MASK64, PERM, RIGHT_ROWS, bits_from_bytes, cross_swap,
    hash_bytes, mix, permute_lanes, sbox_lanes,
)


def scalar_sbox(x: int) -> int:
    a = [(x >> i) & 1 for i in range(9)]
    b = [a[i] ^ ((1 ^ a[(i + 1) % 9]) & a[(i + 2) % 9]) for i in range(9)]
    return sum(v << i for i, v in enumerate(b))


def linear_matrix(rows, swapped=False):
    """Rows of the 576 x 576 GF(2) split Mix layer, as integer bitsets."""
    words = 18 if swapped else 9
    out = []
    for whole_out in range(words):
        half, i = (whole_out // 9, whole_out % 9)
        table = RIGHT_ROWS if swapped and half else LEFT_ROWS
        for z in range(64):
            mask = 0
            for j, a in table[i]:
                src_half = half
                src_i = j
                if swapped:
                    # Linear layer is applied after CrossSwap5.  Its input-basis
                    # coordinates pull back through that involution.
                    src_half, src_i = cross_preimage(src_half, src_i)
                in_bit = (z - a) & 63
                mask ^= 1 << ((src_half * 9 + src_i) * 64 + in_bit)
            out.append(mask)
    return out


def cross_preimage(half: int, i: int):
    for li, ri in ((0, 0), (1, 3), (3, 1), (4, 4), (6, 6)):
        if half == 0 and i == li:
            return 1, ri
        if half == 1 and i == ri:
            return 0, li
    return half, i


def rref(rows):
    pivots = []
    rank = 0
    for col in range(len(rows)):
        p = next((r for r in range(rank, len(rows)) if (rows[r] >> col) & 1), None)
        if p is None:
            continue
        rows[rank], rows[p] = rows[p], rows[rank]
        for r in range(len(rows)):
            if r != rank and ((rows[r] >> col) & 1):
                rows[r] ^= rows[rank]
        pivots.append(col)
        rank += 1
    return rows, pivots


def matrix_inverse(rows):
    n = len(rows)
    aug = [row | (1 << (n + i)) for i, row in enumerate(rows)]
    rank = 0
    for col in range(n):
        p = next((r for r in range(rank, n) if (aug[r] >> col) & 1), None)
        if p is None:
            return None
        aug[rank], aug[p] = aug[p], aug[rank]
        for r in range(n):
            if r != rank and ((aug[r] >> col) & 1):
                aug[r] ^= aug[rank]
        rank += 1
    return [(row >> n) & ((1 << n) - 1) for row in aug]


def apply_matrix(rows, value: int) -> int:
    out = 0
    for i, row in enumerate(rows):
        if (row & value).bit_count() & 1:
            out |= 1 << i
    return out


def support_diffusion(version: int, rounds: int, start_word: int = 0,
                      start_bit: int = 0):
    lanes = 9 if version == 1 else 18
    support = [0] * lanes
    support[start_word] = 1 << start_bit
    for _ in range(rounds):
        halves = [support[:9]]
        if version == 2:
            halves.append(support[9:])
        mixed_halves = []
        for half in halves:
            sf = half
            s = [sf[i] | sf[(i + 1) % 9] | sf[(i + 2) % 9] for i in range(9)]
            mixed_halves.append(permute_lanes(s))
        if version == 2:
            mixed_halves[0], mixed_halves[1] = cross_swap(*mixed_halves)
        support = []
        for h, half in enumerate(mixed_halves):
            rows = RIGHT_ROWS if version == 2 and h else LEFT_ROWS
            for row in rows:
                m = 0
                for j, a in row:
                    m |= rotl_support(half[j], a)
                support.append(m)
    return support


def rotl_support(mask: int, n: int) -> int:
    n &= 63
    return ((mask << n) | (mask >> (64 - n))) & MASK64 if n else mask


def OR_ALL(values):
    out = 0
    for value in values:
        out |= value
    return out


def main():
    started = time.time()
    sbox = [scalar_sbox(x) for x in range(512)]
    ddt = [[0] * 512 for _ in range(512)]
    for a in range(1, 512):
        for x in range(512):
            ddt[a][sbox[x] ^ sbox[x ^ a]] += 1
    # Walsh transform all output masks at once.
    cols = []
    for b in range(512):
        f = [(-1 if ((b & sbox[x]).bit_count() & 1) else 1) for x in range(512)]
        for step in (1, 2, 4, 8, 16, 32, 64, 128, 256):
            for start in range(0, 512, 2 * step):
                for i in range(start, start + step):
                    f[i], f[i + step] = f[i] + f[i + step], f[i] - f[i + step]
        cols.append(f)
    linearity = max(abs(cols[b][a]) for b in range(1, 512) for a in range(512))

    v1 = linear_matrix(LEFT_ROWS)
    v1t = linear_matrix(LEFT_ROWS, swapped=False)
    # Transpose rows in bit coordinate space.
    v1t = [sum(1 << i for i, row in enumerate(v1) if (row >> j) & 1)
           for j in range(576)]
    v1_inv = matrix_inverse(v1)
    assert v1_inv is not None
    inverse_weights = [row.bit_count() for row in v1_inv]

    v2 = linear_matrix(LEFT_ROWS, swapped=True)
    v2_inv = matrix_inverse(v2)
    assert v2_inv is not None
    v2_inverse_weights = [row.bit_count() for row in v2_inv]

    # Check every possible 1-, 2-, and 3-bit input support for the claimed
    # branch numbers.  This is over bit positions, as Section 5.2 states.
    bn = {}
    for w in (1, 2):
        values = []
        for bits in itertools.combinations(range(576), w):
            x = sum(1 << i for i in bits)
            values.append(w + apply_matrix(v1, x).bit_count())
        bn[w] = min(values)

    sbox_preimages = len(set(sbox))
    result = {
        "source": {
            "pdf": "wchain-spec.pdf",
            "pdf_sha256": hashlib.sha256(open("wchain-spec.pdf", "rb").read()).hexdigest(),
            "spec_text": "wchain-spec.txt",
            "model": "wchain.py",
            "model_sha256": hashlib.sha256(open("wchain.py", "rb").read()).hexdigest(),
        },
        "sbox": {
            "distinct_outputs": sbox_preimages,
            "bijective": sbox_preimages == 512,
            "ddt_max": max(max(row) for row in ddt[1:]),
            "lat_max_abs": linearity // 2,
        },
        "v1_mix": {
            "rank": len(rref(v1.copy())[1]),
            "transpose_rank": len(rref(v1t.copy())[1]),
            "row_weight_histogram": {
                str(w): sum(row.bit_count() == w for row in v1)
                for w in sorted(set(row.bit_count() for row in v1))
            },
            "ones": sum(row.bit_count() for row in v1),
            "inverse_ones": sum(inverse_weights),
            "inverse_weight_min": min(inverse_weights),
            "inverse_weight_max": max(inverse_weights),
            "branch_number_1_2_3": bn,
        },
        "v2_split_mix": {
            "rank": len(rref(v2.copy())[1]),
            "inverse_ones": sum(v2_inverse_weights),
            "inverse_weight_min": min(v2_inverse_weights),
            "inverse_weight_max": max(v2_inverse_weights),
        },
        "forward_support_minima": {},
        "boundary_hashes": {},
        "elapsed_seconds": time.time() - started,
    }
    lengths = (0, 1, 7, 8, 63, 64, 143, 144, 145, 287, 288, 289)
    for version in (1, 2):
        words = 9 if version == 1 else 18
        for rounds in range(1, 5):
            stats = []
            for w in range(words):
                for z in range(64):
                    support = support_diffusion(version, rounds, w, z)
                    stats.append({
                        "active_bits": sum(x.bit_count() for x in support),
                        "active_lanes": sum(bool(x) for x in support),
                        "active_z_columns": OR_ALL(support).bit_count(),
                        "active_split_columns": sum(x.bit_count() for x in support),
                    })
            result["forward_support_minima"][f"v{version}/round{rounds}"] = {
                key: min(s[key] for s in stats)
                for key in ("active_bits", "active_lanes", "active_z_columns",
                            "active_split_columns")
            }
    for version, digest_bytes in ((1, 64), (2, 128)):
        for n in lengths:
            patterns = {
                "zero": bytes(n),
                "ff": bytes([255]) * n,
                "counter": bytes(i & 255 for i in range(n)),
            }
            for name, data in patterns.items():
                digest = hash_bytes(version, data)
                assert len(digest) == digest_bytes
                result["boundary_hashes"][f"v{version}/{n}/{name}"] = digest.hex()
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
