#!/usr/bin/env python3
"""Audit source-supported MasterCube state/rate readings.

This imports the shared scalar implementation, then corrects its MixColumns
reading to follow Figure 5: M1 acts on both parity triples of slice z=0 and
M2 acts on both parity triples of slice z=1.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import mastercube_base as mc


HERE = Path(__file__).resolve().parent
BASE_SHA256 = hashlib.sha256((HERE / "mastercube_base.py").read_bytes()).hexdigest()
SOURCE_SHA256 = "cc5b51b21af90a1331f83ebc03ac1a0452c60dd5f7e5661b84266beb7c9c21e9"


def corrected_mix_columns(
    state: list[list[list[int]]],
    m1: tuple[tuple[int, ...], ...] = mc.M_MIX_COL_1,
    m2: tuple[tuple[int, ...], ...] = mc.M_MIX_COL_2,
) -> None:
    for x in range(8):
        for z in range(2):
            matrix = m1 if z == 0 else m2
            for ys in ((0, 2, 4), (1, 3, 5)):
                vector = tuple(state[x][y][z] for y in ys)
                for y, value in zip(ys, mc.mat_vec_mul(matrix, vector)):
                    state[x][y][z] = value


mc.mix_columns = corrected_mix_columns


def bits_of_hex(value: str) -> str:
    return "".join(f"{int(nibble, 16):04b}" for nibble in value)


def first_difference(left: str, right: str) -> dict[str, object]:
    lb, rb = bits_of_hex(left), bits_of_hex(right)
    offset = next((i for i, pair in enumerate(zip(lb, rb)) if pair[0] != pair[1]), None)
    if offset is None:
        raise AssertionError("digests did not differ")
    return {
        "zero_based_bit": offset,
        "left_bit": int(lb[offset]),
        "right_bit": int(rb[offset]),
        "zero_based_hex_nibble": offset // 4,
        "left_nibble": left[offset // 4],
        "right_nibble": right[offset // 4],
    }


def independent_self_tests() -> dict[str, object]:
    # The matrices are stated over F2 and multiplied here directly.
    m1m2 = tuple(
        tuple(
            sum(mc.M_MIX_COL_1[i][k] * mc.M_MIX_COL_2[k][j] for k in range(3)) & 1
            for j in range(3)
        )
        for i in range(3)
    )
    m2m1 = tuple(
        tuple(
            sum(mc.M_MIX_COL_2[i][k] * mc.M_MIX_COL_1[k][j] for k in range(3)) & 1
            for j in range(3)
        )
        for i in range(3)
    )
    expected_identity = ((1, 0, 0), (0, 1, 0), (0, 0, 1))

    state = mc.empty_state()
    for x in range(8):
        for y in range(6):
            for z in range(2):
                state[x][y][z] = (0x9E37 * (1 + x + 8 * y + 48 * z)) & mc.MASK16
    exact_inverse_ok = True
    literal_inverse_failed = False
    for i in range(18):
        test = mc.clone_state(state)
        mc.round_forward(test, i)
        mc.round_inverse_exact(test, i)
        exact_inverse_ok &= test == state

        literal = mc.clone_state(state)
        mc.round_forward(literal, i)
        mc.round_inverse_literal(literal, i)
        literal_inverse_failed |= literal != state

    return {
        "mixcolumns_matrices_are_mutual_inverses": m1m2 == expected_identity == m2m1,
        "exact_round_inverse_all_18_indices": exact_inverse_ok,
        "literal_algorithm2_non_inversion_all_18_indices": literal_inverse_failed,
        "base_module_self_tests": mc.self_tests(),
    }


def main() -> None:
    branch = "exactzip"
    message_hex = "5D9B"
    hash_bits = 512
    readings = {
        "math_xyz": mc.Serialization("xyz", "+++", "msb"),
        "storage_yxz": mc.Serialization("yxz", "+++", "msb"),
    }
    digests: dict[str, str] = {}
    for name, reading in readings.items():
        digests[name] = mc.mastercube(
            bytes.fromhex(message_hex),
            hash_bits,
            branch,
            reading,
            absorb_rate_side="front",
            squeeze_rate_side="front",
        ).hex().upper()

    result = {
        "source": {
            "url": (
                "https://cdn.jsdelivr.net/gh/ngcc-dev/ngcc-harness@"
                "dc66c6cb3c06e75bdea0048e21fa4e13c63f00af/hash-17/hash-17-spec.pdf"
            ),
            "pdf_sha256": SOURCE_SHA256,
            "document": "MasterCube v2.0, June 2026",
        },
        "environment": {
            "python": sys.version.split()[0],
            "platform": sys.platform,
            "base_module_sha256": BASE_SHA256,
        },
        "fully_specified_common_convention": {
            "message_bits": 16,
            "message_hex": message_hex,
            "input_bit_order": "leftmost/most-significant bit first",
            "profile": "MasterCube-512",
            "rate_bits": 960,
            "capacity_bits": 576,
            "padding": "pad10*1",
            "cube_f_branch": (
                "exact inverse of the same nine forward rounds, "
                "with constants RC[8],...,RC[0]"
            ),
            "absorb_rate_window": "first 960 bits of the selected linear state order",
            "squeeze_rate_window": "first 960 bits of the selected linear state order",
            "rate_reset_between_messages": True,
            "coordinate_directions": "increasing x,y,z",
            "cell_bit_order": "15 down to 0",
        },
        "differing_readings": {
            "math_xyz": (
                "A[x,y,z], with x the outer linear index, matching the "
                "mathematical notation in Section 2"
            ),
            "storage_yxz": (
                "A[y,x,z], with y the outer linear index, matching the prose's "
                "6-by-8-by-2 uint16_t C array where x ranges over 8"
            ),
        },
        "full_digests": digests,
        "sha256_of_full_digest_bytes": {
            name: hashlib.sha256(bytes.fromhex(value)).hexdigest()
            for name, value in digests.items()
        },
        "first_differing_bit": first_difference(digests["math_xyz"], digests["storage_yxz"]),
        "official_vector": {
            "full_digest": (
                "C6ADAAFAC38E7BDAA6EAF589376AACCE00D7DCA0B5AC9F6282C6082637B0196"
                "B42AB3C3C6D8F2DA9D43E7B81FC17C3715CE5DDB7B0EA988AAC782925336B3FF7"
            ),
            "matches_math_xyz": False,
            "matches_storage_yxz": False,
        },
        "self_tests": independent_self_tests(),
    }
    (HERE / "bridge-audit.json").write_text(
        json.dumps(result, indent=2) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    main()
