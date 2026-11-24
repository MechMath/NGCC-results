#!/usr/bin/env python3
"""Independent executable MOZI reference model from hash-20-spec.pdf.

Bit convention used here
------------------------
The paper indexes state bits by 0 <= i < 2048 and maps
i = (4*x + y)*128 + z, where i increases within a 128-bit lane.
We identify that numeric lane bit index z with the paper's bit coordinate z.

For byte strings, input bits are consumed most-significant-bit first within
each byte and output bits are serialized the same way.  This byte convention
is made explicit because the specification text defines bit strings but not
their representation as hexadecimal bytes.
"""

from __future__ import annotations

import hashlib
import json
import platform
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable


LANE_BITS = 128
LANE_MASK = (1 << LANE_BITS) - 1

# Table 2, indexed by the nibble whose x=0 coordinate is its most-significant
# bit (as stated in Section 4.3, p.12).
SBOX_TABLE = (0, 8, 6, 13, 5, 15, 7, 12, 4, 14, 2, 3, 9, 1, 11, 10)

# Table 4.
ROUND_CONSTANTS = (
    0x24, 0x3F, 0x6A, 0x88, 0x85, 0xA3, 0x08, 0xD3,
    0x13, 0x19, 0x8A, 0x2E, 0x03, 0x70, 0x73, 0x44,
    0xA4, 0x09, 0x38, 0x22, 0x29, 0x9F, 0x31, 0xD0,
)

# Table 3.  The first row differs from the illustrative values on p.9:
# p.9 says (0,1,2,3), while Table 3 says (0,14,20,22).
SHIFT_TABLE = (
    (0, 14, 20, 22),
    (0, 13, 68, 91),
    (0, 27, 42, 106),
    (0, 32, 48, 80),
)
SHIFT_P9_EXAMPLE = (
    (0, 1, 2, 3),
    (0, 13, 68, 91),
    (0, 27, 42, 106),
    (0, 32, 48, 80),
)


def sbox_algorithm_bits(bits: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    """Literal Alg. 3 S-box equations; tuple order is x=0,...,3."""
    a0, a1, a2, a3 = bits
    b3 = (a3 & a2) ^ a1
    b1 = (a2 | a1) ^ a0
    b0 = (b3 & a0) ^ a3
    b2 = (b1 & a3) ^ a2
    return b0, b1, b2, b3


def sbox_anf_bits(bits: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    """Literal evaluator of the printed ANF in Section 4.3, p.12."""
    x0, x1, x2, x3 = bits
    y0 = (x3 & x2 & x0) ^ (x1 & x0) ^ x3
    y1 = (x2 & x1) ^ x2 ^ x1 ^ x0
    y2 = (x3 & x0) ^ (x2 & x1) ^ x1
    y3 = (x3 & x2) ^ x1
    return y0, y1, y2, y3


def nibble_to_bits(value: int) -> tuple[int, int, int, int]:
    return tuple((value >> (3 - i)) & 1 for i in range(4))


def bits_to_nibble(bits: Iterable[int]) -> int:
    out = 0
    for bit in bits:
        out = (out << 1) | bit
    return out


def sbox_table(value: int) -> int:
    return SBOX_TABLE[value]


def sbox_algorithm(value: int) -> int:
    return bits_to_nibble(sbox_algorithm_bits(nibble_to_bits(value)))


def sbox_anf(value: int) -> int:
    return bits_to_nibble(sbox_anf_bits(nibble_to_bits(value)))


def alpha(n: int) -> int:
    """Multiply by alpha in the paper's x^4+x+1 representation."""
    rotated = ((n << 1) | (n >> 3)) & 0xF
    return rotated ^ ((n >> 2) & 1)


def alpha2(n: int) -> int:
    return alpha(alpha(n))


def mds_literal(a: int, b: int, c: int, d: int) -> tuple[int, int, int, int]:
    """Literal matrix rows in Section 2.4.2."""
    return (
        alpha2(a) ^ alpha2(b) ^ alpha(b) ^ c ^ d,
        a ^ alpha(b) ^ b ^ alpha2(c) ^ c ^ alpha2(d) ^ alpha(d) ^ d,
        a ^ b ^ alpha2(c) ^ alpha2(d) ^ alpha(d),
        alpha2(a) ^ a ^ alpha2(b) ^ alpha(b) ^ b ^ c ^ alpha(d) ^ d,
    )


def mds_mul(s: int) -> int:
    """Alg. 4 MUL on a four-bit word."""
    x3 = s & 1
    x2 = (s >> 1) & 1
    x1 = (s >> 2) & 1
    x0 = (s >> 3) & 1
    tmp = x3
    x3 = x2
    x2 = x1
    x1 = x0
    x0 = tmp
    x1 ^= x0
    return bits_to_nibble((x0, x1, x2, x3))


def mds_algorithm(a: int, b: int, c: int, d: int) -> tuple[int, int, int, int]:
    """Literal Alg. 4 operations, componentwise after S vectors are nibbles."""
    s0, s1, s2, s3 = a, b, c, d
    s2 ^= s3
    s0 ^= s1
    s1 = mds_mul(s1)
    s3 = mds_mul(s3)
    s1 ^= s2
    s3 ^= s0
    s0 = mds_mul(s0)
    s2 = mds_mul(s2)
    s0 = mds_mul(s0)
    s2 = mds_mul(s2)
    s2 ^= s3
    s0 ^= s1
    s1 ^= s2
    s3 ^= s0
    return s0, s1, s2, s3


def swap_middle_two_bits(value: int) -> int:
    """Map tuple positions (x0,x1,x2,x3) -> (x0,x3,x2,x1)."""
    bits = nibble_to_bits(value)
    return bits_to_nibble((bits[0], bits[3], bits[2], bits[1]))


def mds_algorithm_equiv(
        a: int, b: int, c: int, d: int) -> tuple[int, int, int, int]:
    """Alg. 4 after the coordinate map that makes its MUL equal Section 2.4.2.

    The printed matrix maps (x1,x2,x3,x0 xor x1).  The literal Alg. 4 MUL
    maps (x3,x0 xor x3,x1,x2).  Conjugating MUL by the fixed bit transposition
    (x1 x3) makes the two matrices identical.  We use that conjugation only
    for this independently selectable implementation, not to hide the literal
    mismatch: it is reported by the self-tests and report.
    """
    mapped = tuple(swap_middle_two_bits(v) for v in (a, b, c, d))
    out = mds_algorithm(*mapped)
    return tuple(swap_middle_two_bits(v) for v in out)


@dataclass(frozen=True)
class Model:
    sbox: Callable[[int], int]
    shift: tuple[tuple[int, int, int, int], ...]
    mds: Callable[[int, int, int, int], tuple[int, int, int, int]]
    sbox_name: str
    shift_name: str
    mds_name: str


def get_bit(lane: int, z: int) -> int:
    return (lane >> z) & 1


def set_bit(lane: int, z: int, bit: int) -> int:
    if bit:
        return lane | (1 << z)
    return lane & ~(1 << z)


def rotate_formula(lane: int, rho: int) -> int:
    """D[z] = C[(z-rho) mod 128], exactly Eq. (4)."""
    if rho == 0:
        return lane
    return ((lane << rho) | (lane >> (LANE_BITS - rho))) & LANE_MASK


def extract_nibble(state: list[list[int]], y: int, z: int) -> int:
    return sum(get_bit(state[x][y], z) << (3 - x) for x in range(4))


def insert_nibble(state: list[list[int]], y: int, z: int, value: int) -> None:
    for x in range(4):
        bit = (value >> (3 - x)) & 1
        state[x][y] = set_bit(state[x][y], z, bit)


def permute(state_in: list[list[int]], rounds: int, model: Model) -> list[list[int]]:
    a = [row[:] for row in state_in]
    for i in range(rounds):
        # S-box: one nibble across x at each fixed (y,z).
        b = [[0] * 4 for _ in range(4)]
        for y in range(4):
            for z in range(LANE_BITS):
                insert_nibble(b, y, z, model.sbox(extract_nibble(a, y, z)))

        # MixColumn: at each fixed z, the four B[.,y,z] nibbles (each across
        # x) are the four GF(2^4) symbols of the printed matrix.
        c = [[0] * 4 for _ in range(4)]
        for z in range(LANE_BITS):
            values = tuple(extract_nibble(b, y, z) for y in range(4))
            out = model.mds(*values)
            for y in range(4):
                insert_nibble(c, y, z, out[y])

        # ShiftRow, exact direction given by Eq. (4).
        d = [[0] * 4 for _ in range(4)]
        rho = model.shift[i % 4]
        for x in range(4):
            for y in range(4):
                d[x][y] = rotate_formula(c[x][y], rho[y])

        # AddConstant: little-endian byte at the LSB of D[3,3].
        d[3][3] ^= ROUND_CONSTANTS[i]
        a = d
    return a


def bytes_to_bits(data: bytes) -> list[int]:
    return [(byte >> (7 - i)) & 1 for byte in data for i in range(8)]


def bits_to_bytes(bits: Iterable[int]) -> bytes:
    seq = list(bits)
    if len(seq) % 8:
        raise ValueError("output bit length is not a multiple of eight")
    return bytes(bits_to_nibble(seq[i:i + 8]) for i in range(0, len(seq), 8))


def state_to_external_bits(state: list[list[int]]) -> list[int]:
    return [get_bit(state[x][y], z) for x in range(4) for y in range(4)
            for z in range(LANE_BITS)]


def bits_to_state(bits: list[int]) -> list[list[int]]:
    if len(bits) != 2048:
        raise ValueError("MOZI state is exactly 2048 bits")
    state = [[0] * 4 for _ in range(4)]
    for i, bit in enumerate(bits):
        lane_offset, z = divmod(i, LANE_BITS)
        x, y = divmod(lane_offset, 4)
        state[x][y] = set_bit(state[x][y], z, bit)
    return state


def xor_rate_block(state_bits: list[int], block: list[int], rate: int) -> None:
    if len(block) != rate:
        raise ValueError("wrong block length")
    for i, bit in enumerate(block):
        state_bits[i] ^= bit


def pad_message(message: bytes, rate: int) -> list[int]:
    bits = bytes_to_bits(message)
    bits.append(1)
    bits.extend([0] * ((-len(bits)) % rate))
    return bits


def sponge(message: bytes, digest_bits: int, rate: int, rounds: int,
           model: Model, output_bits: int | None = None) -> bytes:
    ell = digest_bits if output_bits is None else output_bits
    padded = pad_message(message, rate)
    state = [[0] * 4 for _ in range(4)]
    for pos in range(0, len(padded), rate):
        block = padded[pos:pos + rate]
        state_bits = state_to_external_bits(state)
        xor_rate_block(state_bits, block, rate)
        state = permute(bits_to_state(state_bits), rounds, model)

    state_bits = state_to_external_bits(state)
    z = state_bits[:rate]
    lambda_blocks = ell // rate
    for _ in range(lambda_blocks):
        state = permute(state, rounds, model)
        state_bits = state_to_external_bits(state)
        z.extend(state_bits[:rate])
    return bits_to_bytes(z[:ell])


def feed_forward_sponge(message: bytes, digest_bits: int, rate: int, rounds: int,
                        model: Model) -> bytes:
    capacity = 2048 - rate
    if digest_bits > capacity:
        raise ValueError("digest exceeds capacity")
    padded = pad_message(message, rate)
    blocks = [padded[pos:pos + rate] for pos in range(0, len(padded), rate)]
    state = [[0] * 4 for _ in range(4)]
    for i, block in enumerate(blocks):
        state_bits = state_to_external_bits(state)
        xor_rate_block(state_bits, block, rate)
        if i + 1 == len(blocks):
            state_bits[rate + capacity - 1] ^= 1
        permuted = permute(bits_to_state(state_bits), rounds, model)
        # I <- (0^r || LSB_c(I)) xor p(I): permuted rate, and the old
        # capacity XOR the permuted capacity.
        permuted_bits = state_to_external_bits(permuted)
        merged = permuted_bits[:rate] + [
            state_bits[i] ^ permuted_bits[i] for i in range(rate, 2048)
        ]
        state = bits_to_state(merged)
    # LSB_h(I) is the final h bits of the 2048-bit string.  Since c >= h,
    # these lie wholly in the capacity after the rate prefix.
    full = state_to_external_bits(state)
    return bits_to_bytes(full[2048 - digest_bits:])


MODELS = {
    ("table", "table", "literal"): Model(
        sbox_table, SHIFT_TABLE, mds_literal, "table", "table", "literal"),
    ("table", "table", "algorithm4"): Model(
        sbox_table, SHIFT_TABLE, mds_algorithm_equiv,
        "table", "table", "algorithm4_equiv"),
    ("table", "table", "algorithm4_raw"): Model(
        sbox_table, SHIFT_TABLE, mds_algorithm,
        "table", "table", "algorithm4_raw"),
    ("table", "p9", "literal"): Model(
        sbox_table, SHIFT_P9_EXAMPLE, mds_literal, "table", "p9", "literal"),
    ("anf", "table", "literal"): Model(
        sbox_anf, SHIFT_TABLE, mds_literal, "anf", "table", "literal"),
}

INSTANCES = {
    "Mozi-384": ("sponge", 384, 1280, 20),
    "Mozi-512": ("sponge", 512, 1024, 20),
    "Mozi-384-XOF": ("sponge", 384, 1280, 20),
    "Mozi-512-XOF": ("sponge", 512, 1024, 20),
    "Mozi-768": ("ff", 768, 1216, 24),
    "Mozi-1024": ("ff", 1024, 960, 24),
}


def mozi(instance: str, message: bytes, model: Model) -> bytes:
    mode, h, r, rounds = INSTANCES[instance]
    if mode == "sponge":
        # XOF fixes h=0 in the notation, but for these two requested fixed
        # output widths the squeeze path is identical to the named digest.
        return sponge(message, h, r, rounds, model)
    return feed_forward_sponge(message, h, r, rounds, model)


def differing_bits(a: bytes, b: bytes) -> int:
    if len(a) != len(b):
        raise ValueError("digest lengths differ")
    return sum((x ^ y).bit_count() for x, y in zip(a, b))


def tests() -> dict:
    sbox_algorithm_values = [sbox_algorithm(i) for i in range(16)]
    sbox_anf_values = [sbox_anf(i) for i in range(16)]
    sbox_diffs = [(i, SBOX_TABLE[i] ^ sbox_anf_values[i])
                  for i in range(16) if SBOX_TABLE[i] != sbox_anf_values[i]]
    mds_mismatches = []
    mds_equiv_mismatches = []
    for a in range(16):
        for b in range(16):
            for c in range(16):
                for d in range(16):
                    if mds_literal(a, b, c, d) != mds_algorithm(a, b, c, d):
                        mds_mismatches.append((a, b, c, d))
                    if mds_literal(a, b, c, d) != mds_algorithm_equiv(a, b, c, d):
                        mds_equiv_mismatches.append((a, b, c, d))
    return {
        "sbox_table": list(SBOX_TABLE),
        "sbox_algorithm": sbox_algorithm_values,
        "sbox_table_equals_algorithm_all16": tuple(sbox_algorithm_values) == SBOX_TABLE,
        "sbox_anf": sbox_anf_values,
        "sbox_table_vs_anf_differences": sbox_diffs,
        "sbox_difference_output_bit_indices": sorted({
            y for _, delta in sbox_diffs for y in range(4) if (delta >> (3 - y)) & 1
        }),
        "sbox_table_vs_anf_all_differences_are_single_y2": all(
            delta == 0b0010 for _, delta in sbox_diffs
        ),
        "mds_literal_equals_algorithm4_all65536": not mds_mismatches,
        "mds_mismatch_count": len(mds_mismatches),
        "mds_literal_equals_algorithm4_after_x1_x3_conjugation_all65536":
            not mds_equiv_mismatches,
        "mds_equiv_mismatch_count": len(mds_equiv_mismatches),
    }


def main() -> None:
    messages = {
        "empty": b"",
        "00": b"\x00",
        "abc": b"abc",
        "seq_00_to_9f": bytes(range(160)),
    }
    result = {
        "environment": {
            "python": sys.version,
            "platform": platform.platform(),
            "spec_sha256": hashlib.sha256(Path(
                "/home/mmat/mmat-preview/campaigns/rebuild-20261119/runs/"
                "rebuild-104-hash-20-ds02/slots/orch-graph/orch/hash-20-spec.pdf"
            ).read_bytes()).hexdigest(),
            "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        },
        "conventions": {
            "state": "i=(4*x+y)*128+z; numeric lane bit z is paper coordinate z",
            "bytes_to_bits": "MSB first within each input byte",
            "bits_to_bytes": "MSB first within each output byte",
            "rate_bits": "external indices 0..r-1 in increasing order",
            "absorb_padding": "M || 1 || zeros to a multiple of r",
            "ff_final_capacity_pad": "external capacity bit index r+c-1 set to 1",
            "ff_feedback": "I=(0^r || LSB_c(I)) XOR p(I)",
            "shiftrow": "D[x,y,z]=C[x,y,(z-rho) mod 128]",
            "round_constant": "RC[i] XORed into integer bits z=0..7 of D[3,3]",
        },
        "tests": tests(),
        "digests": {},
    }
    if not (result["tests"]["sbox_table_equals_algorithm_all16"]
            and result["tests"]["sbox_table_vs_anf_all_differences_are_single_y2"]
            and result["tests"][
                "mds_literal_equals_algorithm4_after_x1_x3_conjugation_all65536"
            ]):
        raise SystemExit("self-test failure")

    comparisons = {
        "shift_table_vs_p9": (("table", "table", "literal"), ("table", "p9", "literal")),
        "sbox_table_vs_anf": (("table", "table", "literal"), ("anf", "table", "literal")),
        "mds_literal_vs_algorithm4_raw": (
            ("table", "table", "literal"), ("table", "table", "algorithm4_raw")),
    }
    for name, message in messages.items():
        result["digests"][name] = {
            "message_hex": message.hex(),
            "instances": {},
        }
        for instance in ("Mozi-384", "Mozi-768", "Mozi-1024"):
            row = {"variant_hex": {}}
            values = {}
            for key, model in MODELS.items():
                variant = f"{model.sbox_name}/{model.shift_name}/{model.mds_name}"
                value = mozi(instance, message, model)
                values[key] = value
                row["variant_hex"][variant] = value.hex()
            for compare_name, (base_key, other_key) in comparisons.items():
                row[compare_name] = {
                    "different_bits": differing_bits(values[base_key], values[other_key]),
                    "different_hex_characters": sum(
                        a != b for a, b in zip(
                            values[base_key].hex(), values[other_key].hex())
                    ),
                }
            result["digests"][name]["instances"][instance] = row
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
