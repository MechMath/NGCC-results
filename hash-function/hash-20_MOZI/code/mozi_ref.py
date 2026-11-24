#!/usr/bin/env python3
"""
Independent reference model of the MOZI hash specification.

Source allowed for this implementation:
  hash-20-spec.pdf, SHA-256
  1c611656c47a7d708dc47449c5fdf2aa4f524e53362b08242daedc57932dbb86

Conventions fixed from the paper:
  * The 2048 state bits are a bit string indexed by i.  Bit i is the state
    coordinate (x,y,z) with i=(4*x+y)*128+z.
  * The first message bit occupies external state index 0.
  * For byte input, the default serializer is MSB-first: byte bit 7 is the
    first bit.  The paper gives no explicit byte-to-bit convention, so a
    little-endian serializer is also available and reported separately.
  * For nibbles, x0 is the most-significant bit, as stated on p.12.
  * Lookup S-box is literal Table 2.  ANF S-box is a literal evaluation of
    the four formulas printed on p.12.
  * MixColumn follows Algorithm 4, which is the executable definition used
    by this model.
"""

from __future__ import annotations

import argparse
import hashlib
import inspect
import json
import os
import platform
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


SPEC_SHA256 = "1c611656c47a7d708dc47449c5fdf2aa4f524e53362b08242daedc57932dbb86"
LANES = 16
LANE_BITS = 128
STATE_BITS = LANES * LANE_BITS

SBOX_TABLE = (0x0, 0x8, 0x6, 0xD, 0x5, 0xF, 0x7, 0xC,
              0x4, 0xE, 0x2, 0x3, 0x9, 0x1, 0xB, 0xA)

SHIFT_ROWS = (
    (0, 14, 20, 22),
    (0, 13, 68, 91),
    (0, 27, 42, 106),
    (0, 32, 48, 80),
)

ROUND_CONSTANTS = (
    0x24, 0x3F, 0x6A, 0x88, 0x85, 0xA3, 0x08, 0xD3,
    0x13, 0x19, 0x8A, 0x2E, 0x03, 0x70, 0x73, 0x44,
    0xA4, 0x09, 0x38, 0x22, 0x29, 0x9F, 0x31, 0xD0,
)


def sb_table(x: int) -> int:
    """Literal Table 2 lookup."""
    return SBOX_TABLE[x]


def sb_anf(x: int) -> int:
    """Literal p.12 ANF, with x0 the most-significant bit."""
    x0 = (x >> 3) & 1
    x1 = (x >> 2) & 1
    x2 = (x >> 1) & 1
    x3 = x & 1
    y0 = x3 * x2 * x0 ^ x1 * x0 ^ x3
    y1 = x2 * x1 ^ x2 ^ x1 ^ x0
    y2 = x3 * x0 ^ x2 * x1 ^ x1
    y3 = x3 * x2 ^ x1
    return (y0 << 3) | (y1 << 2) | (y2 << 1) | y3


SBOXES = {"table": sb_table, "anf": sb_anf}


def lane_index(x: int, y: int) -> int:
    return 4 * x + y


def state_bit_to_lane_z(i: int) -> tuple[int, int]:
    if not 0 <= i < STATE_BITS:
        raise ValueError(f"state bit index out of range: {i}")
    lane, z = divmod(i, LANE_BITS)
    return lane, z


def empty_state() -> list[int]:
    return [0] * LANES


def state_from_bitstring(bits: str) -> list[int]:
    if len(bits) > STATE_BITS or any(c not in "01" for c in bits):
        raise ValueError("state bit string must have at most 2048 binary digits")
    state = empty_state()
    for i, c in enumerate(bits):
        if c == "1":
            lane, z = state_bit_to_lane_z(i)
            state[lane] |= 1 << z
    return state


def state_to_bitstring(state: list[int], width: int = STATE_BITS) -> str:
    if not 0 <= width <= STATE_BITS:
        raise ValueError("width outside state")
    return "".join(
        "1" if (state[lane] >> z) & 1 else "0"
        for lane, z in (state_bit_to_lane_z(i) for i in range(width))
    )


def bytes_to_bitstring(data: bytes, byte_order: str = "msbf") -> str:
    if byte_order == "msbf":
        return "".join(f"{b:08b}" for b in data)
    if byte_order == "lsbf":
        return "".join(f"{b:08b}"[::-1] for b in data)
    raise ValueError(f"unknown byte order: {byte_order}")


def get_nibble(state: list[int], y: int, z: int) -> int:
    """Return B[0..3,y,z] as a nibble, with x=0 as its MSB."""
    return (
        (((state[lane_index(0, y)] >> z) & 1) << 3)
        | (((state[lane_index(1, y)] >> z) & 1) << 2)
        | (((state[lane_index(2, y)] >> z) & 1) << 1)
        | ((state[lane_index(3, y)] >> z) & 1)
    )


def set_nibble(state: list[int], y: int, z: int, value: int) -> None:
    """Set B[0..3,y,z], with x=0 as its MSB."""
    for x in range(4):
        bit = (value >> (3 - x)) & 1
        mask = 1 << z
        lane = lane_index(x, y)
        if bit:
            state[lane] |= mask
        else:
            state[lane] &= ~mask


def sub_bytes(state: list[int], sbox_name: str,
              trace: dict[str, int] | None = None) -> list[int]:
    sbox = SBOXES[sbox_name]
    out = empty_state()
    for y in range(4):
        for z in range(LANE_BITS):
            x = get_nibble(state, y, z)
            value = sbox(x)
            set_nibble(out, y, z, value)
            if trace is not None:
                a = sb_anf(x)
                t = sb_table(x)
                trace["sbox_invocations"] += 1
                trace["sbox_inputs_with_different_selectors"] += int(a != t)
                trace["sbox_output_bit_difference_counts_y0"] += (a >> 3) != (t >> 3)
                trace["sbox_output_bit_difference_counts_y1"] += ((a >> 2) & 1) != ((t >> 2) & 1)
                trace["sbox_output_bit_difference_counts_y2"] += ((a >> 1) & 1) != ((t >> 1) & 1)
                trace["sbox_output_bit_difference_counts_y3"] += (a & 1) != (t & 1)
                trace["sbox_difference_masks"][str(a ^ t)] = (
                    trace["sbox_difference_masks"].get(str(a ^ t), 0) + 1
                )
    return out


def alpha(value: int) -> int:
    """Algorithm 4 MUL: (x0,x1,x2,x3)->(x3,x0^x1,x1,x2)."""
    x0 = (value >> 3) & 1
    x1 = (value >> 2) & 1
    x2 = (value >> 1) & 1
    x3 = value & 1
    return (x3 << 3) | ((x0 ^ x1) << 2) | (x1 << 1) | x2


def alpha_printed_matrix(value: int) -> int:
    """Literal alpha matrix from p.8, with x0 most significant."""
    x0 = (value >> 3) & 1
    x1 = (value >> 2) & 1
    x2 = (value >> 1) & 1
    x3 = value & 1
    return (x1 << 3) | (x2 << 2) | (x3 << 1) | (x0 ^ x1)


def mix_columns_one(s0: int, s1: int, s2: int, s3: int) -> tuple[int, int, int, int]:
    """Literal Algorithm 4 on one z slice."""
    s2 ^= s3
    s0 ^= s1
    s1 = alpha(s1)
    s3 = alpha(s3)
    s1 ^= s2
    s3 ^= s0
    s0 = alpha(s0)
    s2 = alpha(s2)
    s0 = alpha(s0)
    s2 = alpha(s2)
    s2 ^= s3
    s0 ^= s1
    s1 ^= s2
    s3 ^= s0
    return s0, s1, s2, s3


def mix_columns_one_formal(s0: int, s1: int, s2: int, s3: int) -> tuple[int, int, int, int]:
    """Literal p.8 row expression using the separately printed alpha matrix."""
    a, b, c, d = s0, s1, s2, s3
    a2 = alpha_printed_matrix(alpha_printed_matrix(a))
    b2 = alpha_printed_matrix(alpha_printed_matrix(b))
    c2 = alpha_printed_matrix(alpha_printed_matrix(c))
    d2 = alpha_printed_matrix(alpha_printed_matrix(d))
    return (
        a2 ^ b2 ^ alpha_printed_matrix(b) ^ c ^ d,
        a ^ alpha_printed_matrix(b) ^ b ^ c2 ^ c ^ d2 ^ alpha_printed_matrix(d) ^ d,
        a ^ b ^ c2 ^ d2 ^ alpha_printed_matrix(d),
        a2 ^ a ^ b2 ^ alpha_printed_matrix(b) ^ b ^ c ^ alpha_printed_matrix(d) ^ d,
    )


MIX_COLUMNS = {
    "algorithm4": mix_columns_one,
    "formal": mix_columns_one_formal,
}


def mix_columns(state: list[int], mds_name: str) -> list[int]:
    transform = MIX_COLUMNS[mds_name]
    out = empty_state()
    for z in range(LANE_BITS):
        values = [get_nibble(state, y, z) for y in range(4)]
        for y, value in enumerate(transform(*values)):
            set_nibble(out, y, z, value)
    return out


def shift_rows(state: list[int], round_index: int) -> list[int]:
    rotations = SHIFT_ROWS[round_index % 4]
    out = empty_state()
    for x in range(4):
        for y in range(4):
            lane = lane_index(x, y)
            out[lane] = rotate_right_128(state[lane], rotations[y])
    return out


def rotate_right_128(value: int, amount: int) -> int:
    amount %= LANE_BITS
    if amount == 0:
        return value
    return ((value >> amount) | (value << (LANE_BITS - amount))) & ((1 << LANE_BITS) - 1)


def add_constant(state: list[int], round_index: int) -> list[int]:
    # D[3,3,z] for 0 <= z <= 7 is external bits 1920..1927.  Adding RC as a
    # little-endian byte to that lane therefore XORs it into lane bits 0..7.
    out = state.copy()
    out[lane_index(3, 3)] ^= ROUND_CONSTANTS[round_index]
    return out


def permutation(state: list[int], rounds: int, sbox_name: str,
                mds_name: str = "algorithm4",
                trace: dict[str, object] | None = None) -> list[int]:
    current = state.copy()
    for r in range(rounds):
        current = sub_bytes(current, sbox_name, trace)
        current = mix_columns(current, mds_name)
        current = shift_rows(current, r)
        current = add_constant(current, r)
    return current


def padded_blocks(message_bits: str, rate: int) -> list[str]:
    if rate <= 0 or rate > STATE_BITS:
        raise ValueError("invalid rate")
    padded = message_bits + "1"
    padded += "0" * ((-len(padded)) % rate)
    if len(padded) == 0:
        raise AssertionError("padding always inserts one bit")
    return [padded[i:i + rate] for i in range(0, len(padded), rate)]


def xor_rate_bits(state: list[int], block: str) -> None:
    for i, c in enumerate(block):
        if c == "1":
            lane, z = state_bit_to_lane_z(i)
            state[lane] ^= 1 << z


def xor_capacity_one_at_lsb(state: list[int], capacity: int) -> None:
    # 0^(c-1) || 1 at the end of the full state, i.e. external bit 2047.
    if capacity <= 0:
        raise ValueError("capacity must be positive")
    state[lane_index(3, 3)] ^= 1 << 127


def sponge(message_bits: str, digest_bits: int, rate: int,
           rounds: int, sbox_name: str,
           mds_name: str = "algorithm4",
           trace: dict[str, object] | None = None) -> str:
    capacity = STATE_BITS - rate
    if digest_bits > capacity:
        raise ValueError("sponge digest exceeds capacity")
    state = empty_state()
    blocks = padded_blocks(message_bits, rate)
    for block in blocks:
        xor_rate_bits(state, block)
        state = permutation(state, rounds, sbox_name, mds_name, trace)

    # Algorithm 1 appends MSB_r(I) to Z, then repeats for lambda=floor(l/r).
    output = state_to_bitstring(state, rate)
    lambda_times = digest_bits // rate
    for _ in range(lambda_times):
        state = permutation(state, rounds, sbox_name, mds_name, trace)
        output += state_to_bitstring(state, rate)
    return output[:digest_bits]


def feed_forward_sponge(message_bits: str, digest_bits: int, rate: int,
                        rounds: int, sbox_name: str,
                        mds_name: str = "algorithm4",
                        trace: dict[str, object] | None = None) -> str:
    capacity = STATE_BITS - rate
    if digest_bits > capacity:
        raise ValueError("digest exceeds capacity")
    state = empty_state()
    blocks = padded_blocks(message_bits, rate)
    for i, block in enumerate(blocks, start=1):
        if i != len(blocks):
            xor_rate_bits(state, block)
        else:
            xor_rate_bits(state, block)
            xor_capacity_one_at_lsb(state, capacity)
        permuted = permutation(state, rounds, sbox_name, mds_name, trace)
        # (0^r || LSB_c(I)) XOR p_b(I)
        state = [0] * (rate // LANE_BITS) + state[rate // LANE_BITS:]
        state = [a ^ b for a, b in zip(state, permuted)]
    # T = LSB_h(I): the last h bits of the state bit string.
    return state_to_bitstring(state, STATE_BITS)[-digest_bits:]


INSTANCES = {
    "Mozi-384": dict(mode="sponge", digest_bits=384, rate=1280, rounds=20),
    "Mozi-512": dict(mode="sponge", digest_bits=512, rate=1024, rounds=20),
    "Mozi-768": dict(mode="feed-forward", digest_bits=768, rate=1216, rounds=24),
    "Mozi-1024": dict(mode="feed-forward", digest_bits=1024, rate=960, rounds=24),
    "Mozi-384-XOF": dict(mode="sponge", digest_bits=384, rate=1280, rounds=20),
    "Mozi-512-XOF": dict(mode="sponge", digest_bits=512, rate=1024, rounds=20),
}


def digest_bits(instance: str, message_bits: str, sbox_name: str,
                mds_name: str = "algorithm4",
                trace: dict[str, object] | None = None) -> str:
    p = INSTANCES[instance]
    if p["mode"] == "sponge":
        return sponge(message_bits, p["digest_bits"], p["rate"],
                      p["rounds"], sbox_name, mds_name, trace)
    return feed_forward_sponge(message_bits, p["digest_bits"], p["rate"],
                               p["rounds"], sbox_name, mds_name, trace)


def bits_to_hex(bits: str) -> str:
    if len(bits) % 4:
        raise ValueError("digest bit length must be divisible by four")
    return "".join(f"{int(bits[i:i + 4], 2):x}" for i in range(0, len(bits), 4))


def hex_to_bits(value: str) -> str:
    if any(c not in "0123456789abcdefABCDEF" for c in value):
        raise ValueError("invalid hex input")
    return "".join(f"{int(c, 16):04b}" for c in value)


def new_trace() -> dict[str, object]:
    return {
        "sbox_invocations": 0,
        "sbox_inputs_with_different_selectors": 0,
        "sbox_output_bit_difference_counts_y0": 0,
        "sbox_output_bit_difference_counts_y1": 0,
        "sbox_output_bit_difference_counts_y2": 0,
        "sbox_output_bit_difference_counts_y3": 0,
        "sbox_difference_masks": {},
    }


def self_test() -> dict[str, object]:
    table_results = [sb_table(x) for x in range(16)]
    anf_results = [sb_anf(x) for x in range(16)]
    anf_expected_from_paper = [0x0, 0x8, 0x4, 0xD, 0x7, 0xF, 0x5, 0xC,
                               0x4, 0xE, 0x0, 0x3, 0xB, 0x1, 0x9, 0xA]

    # Bitsliced Algorithm 3 is supposed to implement Table 2.  This is a
    # component-level identity check, not another S-box definition.
    bitslice_results = []
    for x in range(16):
        a = [(x >> (3 - i)) & 1 for i in range(4)]
        b3 = (a[3] & a[2]) ^ a[1]
        b1 = (a[2] | a[1]) ^ a[0]
        b0 = (b3 & a[0]) ^ a[3]
        b2 = (b1 & a[3]) ^ a[2]
        bitslice_results.append((b0 << 3) | (b1 << 2) | (b2 << 1) | b3)

    # Algorithm 4 equals the direct MDS row expression in its printed output
    # order when using Algorithm 4's MUL.  This checks the row expression,
    # separately from the separate alpha-matrix discrepancy recorded below.
    def mul_x(v: int) -> int:
        return alpha(v)

    def mds_direct(a: int, b: int, c: int, d: int) -> tuple[int, int, int, int]:
        row0 = mul_x(mul_x(a)) ^ mul_x(mul_x(b)) ^ mul_x(b) ^ c ^ d
        row1 = a ^ mul_x(b) ^ b ^ mul_x(mul_x(c)) ^ c ^ mul_x(mul_x(d)) ^ mul_x(d) ^ d
        row2 = a ^ b ^ mul_x(mul_x(c)) ^ mul_x(mul_x(d)) ^ mul_x(d)
        row3 = mul_x(mul_x(a)) ^ a ^ mul_x(mul_x(b)) ^ mul_x(b) ^ b ^ c ^ mul_x(d) ^ d
        return row0, row1, row2, row3

    mds_identity_exceptions = []
    for a in range(16):
        for b in range(16):
            for c in range(16):
                for d in range(16):
                    if mix_columns_one(a, b, c, d) != mds_direct(a, b, c, d):
                        mds_identity_exceptions.append((a, b, c, d))
                        if len(mds_identity_exceptions) >= 8:
                            break
                if len(mds_identity_exceptions) >= 8:
                    break
            if len(mds_identity_exceptions) >= 8:
                break
        if len(mds_identity_exceptions) >= 8:
            break

    # The MDS branch number is min(nonzero input weight + output weight).
    def mds_branch_number(transform) -> int:
        best = 9
        for a in range(16):
            for b in range(16):
                for c in range(16):
                    for d in range(16):
                        if not (a or b or c or d):
                            continue
                        out = transform(a, b, c, d)
                        weight = (a.bit_count() + b.bit_count() + c.bit_count()
                                  + d.bit_count() + sum(v.bit_count() for v in out))
                        best = min(best, weight)
        return best

    alpha_disagreements = [
        f"{x:x}:{alpha(x):x}!={alpha_printed_matrix(x):x}" for x in range(16)
        if alpha(x) != alpha_printed_matrix(x)
    ]

    # Round rotation/constant indexing and padding boundary checks.
    one = [0] * LANES
    one[0] = 1
    assert rotate_right_128(one[0], 0) == 1
    assert rotate_right_128(1, 1) == 1 << 127
    rc_state = add_constant(empty_state(), 0)
    assert rc_state[lane_index(3, 3)] == 0x24
    assert all(rc_state[i] == 0 for i in range(LANES) if i != lane_index(3, 3))
    assert [len(x) for x in padded_blocks("", 8)] == [8]
    assert padded_blocks("", 8)[0] == "10000000"
    assert [len(x) for x in padded_blocks("1" * 8, 8)] == [8, 8]
    assert padded_blocks("1" * 8, 8) == ["11111111", "10000000"]

    return {
        "table_entries": [f"{x:x}" for x in table_results],
        "anf_entries": [f"{x:x}" for x in anf_results],
        "bitslice_matches_table_for_all_16_inputs": bitslice_results == table_results,
        "anf_matches_literal_evaluation_for_all_16_inputs": anf_results == anf_expected_from_paper,
        "anf_equals_table_on_inputs": [
            f"{x:x}" for x in range(16) if anf_results[x] == table_results[x]
        ],
        "anf_differs_from_table_on_inputs": [
            f"{x:x}" for x in range(16) if anf_results[x] != table_results[x]
        ],
        "anf_xor_table": [f"{x:x}" for x in (a ^ t for a, t in zip(anf_results, table_results))],
        "all_nontrivial_anf_differences_are_y2": all(
            (anf_results[x] ^ table_results[x]) in (0, 2) for x in range(16)
        ),
        "mds_algorithm4_matches_direct_printed_rows_on_all_16_to_4_slices":
            not mds_identity_exceptions,
        "mds_first_exceptions": mds_identity_exceptions,
        "mds_algorithm4_branch_number": mds_branch_number(mix_columns_one),
        "mds_printed_alpha_matrix_branch_number": mds_branch_number(mix_columns_one_formal),
        "algorithm4_alpha_differs_from_printed_alpha_matrix_on": alpha_disagreements,
        "algorithm4_alpha_matches_printed_alpha_matrix_on": [
            f"{x:x}" for x in range(16) if alpha(x) == alpha_printed_matrix(x)
        ],
        "mixcolumns_formal_vs_algorithm4_differing_slices":
            sum(mix_columns_one(*x) != mix_columns_one_formal(*x)
                for a in range(16) for b in range(16) for c in range(16) for d in range(16)
                for x in [(a, b, c, d)]),
        "mixcolumns_first_disagreement": next(
            {
                "input": x,
                "algorithm4": mix_columns_one(*x),
                "formal": mix_columns_one_formal(*x),
            }
            for a in range(16) for b in range(16) for c in range(16) for d in range(16)
            for x in [(a, b, c, d)]
            if mix_columns_one(*x) != mix_columns_one_formal(*x)
        ),
        "padding_boundary_tests": "pass",
        "round_indexing_tests": "pass",
    }


def parse_message(spec: str) -> tuple[str, str]:
    if spec == "empty":
        return "", "special:empty"
    if spec.startswith("ascii:"):
        raw = spec[len("ascii:"):].encode("utf-8")
        return bytes_to_bitstring(raw, "msbf"), f"utf8:{raw.hex()}"
    if spec.startswith("hex:"):
        raw = bytes.fromhex(spec[len("hex:"):])
        return bytes_to_bitstring(raw, "msbf"), f"bytes:{raw.hex()}"
    if spec.startswith("bits:"):
        bits = spec[len("bits:"):]
        if any(c not in "01" for c in bits):
            raise ValueError("bits: input must contain only 0/1")
        return bits, f"bits:{bits}"
    raise ValueError("message must be empty, ascii:..., hex:..., or bits:...")


def run_experiment(messages: Iterable[str], instances: Iterable[str],
                   byte_order: str = "msbf",
                   mds_names: Iterable[str] = ("algorithm4", "formal")) -> dict[str, object]:
    rows = []
    for instance in instances:
        for message_spec in messages:
            raw_input, input_provenance = parse_message(message_spec)
            if byte_order == "lsbf" and message_spec.startswith(("ascii:", "hex:")):
                marker, text = message_spec.split(":", 1)
                raw = text.encode("utf-8") if marker == "ascii" else bytes.fromhex(text)
                raw_input = bytes_to_bitstring(raw, "lsbf")
            traces: dict[str, dict[str, dict[str, object]]] = {}
            results: dict[str, dict[str, str]] = {}
            for mds_name in mds_names:
                traces[mds_name] = {}
                results[mds_name] = {}
                for selector in ("table", "anf"):
                    traces[mds_name][selector] = new_trace()
                    start = time.perf_counter()
                    results[mds_name][selector] = bits_to_hex(
                        digest_bits(instance, raw_input, selector,
                                    mds_name, traces[mds_name][selector])
                    )
                    traces[mds_name][selector]["elapsed_seconds"] = (
                        time.perf_counter() - start
                    )
            sbox_distances = {
                mds_name: sum(
                    a != b for a, b in zip(
                        hex_to_bits(results[mds_name]["table"]),
                        hex_to_bits(results[mds_name]["anf"]),
                    )
                )
                for mds_name in mds_names
            }
            mixcolumn_distances = {
                selector: sum(
                    a != b for a, b in zip(
                        hex_to_bits(results["algorithm4"][selector]),
                        hex_to_bits(results["formal"][selector]),
                    )
                )
                for selector in ("table", "anf")
            } if "algorithm4" in results and "formal" in results else {}
            rows.append({
                "instance": instance,
                "message_input": message_spec,
                "input_provenance": input_provenance,
                "message_bit_length": len(raw_input),
                "padded_block_count": len(padded_blocks(raw_input, INSTANCES[instance]["rate"])),
                "byte_order": byte_order,
                "digests_hex_by_mixcolumns": results,
                "digest_hamming_distance_table_vs_anf_by_mixcolumns": sbox_distances,
                "digest_hamming_distance_algorithm4_vs_formal_by_sbox": mixcolumn_distances,
                "sbox_comparison_traces_by_mixcolumns": traces,
            })
    return {
        "spec_path": "/home/mmat/mmat-preview/campaigns/rebuild-20261119/runs/rebuild-104-hash-20-ds02/slots/orch-graph/orch/hash-20-spec.pdf",
        "spec_sha256": SPEC_SHA256,
        "implementation_path": str(Path(__file__).resolve()),
        "implementation_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "python": sys.version,
        "platform": platform.platform(),
        "self_test": self_test(),
        "results": rows,
        "limitations": [
            "The paper has no byte-to-bit serialization vector. Hex digests here use conventional MSB-first byte bit order.",
            "The paper has no official digest test vector, so this independently defines an executable interpretation rather than validating against an external implementation.",
            "Table 2 and the p.12 ANF are not the same function; no interpretation can make both selectors produce the same digest for all inputs.",
            "The direct p.8 MDS row expression using the separately printed alpha matrix disagrees with Algorithm 4; both choices are exposed in results_msbf.json.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--instances", nargs="+", default=["Mozi-384", "Mozi-768"],
                        choices=list(INSTANCES))
    parser.add_argument("--messages", nargs="+",
                        default=["empty", "ascii:", "ascii:abc", "hex:00ff10",
                                 "hex:00112233445566778899aabbccddeeff"])
    parser.add_argument("--byte-order", choices=["msbf", "lsbf"], default="msbf")
    parser.add_argument("--mds", nargs="+", choices=["algorithm4", "formal"],
                        default=["algorithm4", "formal"])
    args = parser.parse_args()

    if args.self_test:
        result = self_test()
    else:
        result = run_experiment(args.messages, args.instances, args.byte_order, args.mds)
    rendered = json.dumps(result, indent=2, sort_keys=True)
    if args.output:
        args.output.write_text(rendered + "\n")
    print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
