#!/usr/bin/env python3
"""Exploratory independent reference computation for Wish v1.0.

This follows the pinned hash-35-spec.pdf literally.  It supports byte-aligned
messages only, which is sufficient for the byte test vectors used here.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Iterable


# Table 2, pinned PDF p.4.
PARAMS = {
    "Wish-512": {"n": 1024, "lanes": 8, "steps": 9, "rate": 512, "capacity": 512},
    "Wish-1024": {"n": 2048, "lanes": 16, "steps": 12, "rate": 1024, "capacity": 1024},
}


# Equations (2) and (3), pinned PDF p.6.  Output byte i is copied from
# input byte table[i].
MIX_1024 = [
    [0, 16, 32, 48, 1, 17, 33, 49, 64, 80, 96, 112, 65, 81, 97, 113],
    [8, 24, 40, 56, 9, 25, 41, 57, 72, 88, 104, 120, 73, 89, 105, 121],
    [4, 20, 36, 52, 5, 21, 37, 53, 68, 84, 100, 116, 69, 85, 101, 117],
    [12, 28, 44, 60, 13, 29, 45, 61, 76, 92, 108, 124, 77, 93, 109, 125],
    [2, 18, 34, 50, 3, 19, 35, 51, 66, 82, 98, 114, 67, 83, 99, 115],
    [10, 26, 42, 58, 11, 27, 43, 59, 74, 90, 106, 122, 75, 91, 107, 123],
    [6, 22, 38, 54, 7, 23, 39, 55, 70, 86, 102, 118, 71, 87, 103, 119],
    [14, 30, 46, 62, 15, 31, 47, 63, 78, 94, 110, 126, 79, 95, 111, 127],
]

MIX_2048 = [
    [0, 16, 32, 48, 64, 80, 96, 112, 128, 144, 160, 176, 192, 208, 224, 240],
    [8, 24, 40, 56, 72, 88, 104, 120, 136, 152, 168, 184, 200, 216, 232, 248],
    [4, 20, 36, 52, 68, 84, 100, 116, 132, 148, 164, 180, 196, 212, 228, 244],
    [12, 28, 44, 60, 76, 92, 108, 124, 140, 156, 172, 188, 204, 220, 236, 252],
    [2, 18, 34, 50, 66, 82, 98, 114, 130, 146, 162, 178, 194, 210, 226, 242],
    [10, 26, 42, 58, 74, 90, 106, 122, 138, 154, 170, 186, 202, 218, 234, 250],
    [6, 22, 38, 54, 70, 86, 102, 118, 134, 150, 166, 182, 198, 214, 230, 246],
    [14, 30, 46, 62, 78, 94, 110, 126, 142, 158, 174, 190, 206, 222, 238, 254],
    [1, 17, 33, 49, 65, 81, 97, 113, 129, 145, 161, 177, 193, 209, 225, 241],
    [9, 25, 41, 57, 73, 89, 105, 121, 137, 153, 169, 185, 201, 217, 233, 249],
    [5, 21, 37, 53, 69, 85, 101, 117, 133, 149, 165, 181, 197, 213, 229, 245],
    [13, 29, 45, 61, 77, 93, 109, 125, 141, 157, 173, 189, 205, 221, 237, 253],
    [3, 19, 35, 51, 67, 83, 99, 115, 131, 147, 163, 179, 195, 211, 227, 243],
    [11, 27, 43, 59, 75, 91, 107, 123, 139, 155, 171, 187, 203, 219, 235, 251],
    [7, 23, 39, 55, 71, 87, 103, 119, 135, 151, 167, 183, 199, 215, 231, 247],
    [15, 31, 47, 63, 79, 95, 111, 127, 143, 159, 175, 191, 207, 223, 239, 255],
]


# Table 3, pinned PDF p.7.  The right-hand column in the printed table is
# Rcon[12]..Rcon[23].
RCON_HEX = [
    "243f6a8885a308d313198a2e03707344",
    "497fd5110b4610a72632155d06e1e788",
    "92ffab22168c204e4d652aba0cc2ce11",
    "25fe56452c19419c9acb557418859d22",
    "4bfcac8a593282393597aae9300b3b45",
    "96f85815b26505736b2f54d26116778a",
    "2df0b02a64cb0ae7d75fa8a5c32cef15",
    "5be06055c99714ceafbe504a8759de2a",
    "b6c0c1aa932f289d5e7ca0940fb2bd55",
    "6c818354275f513bbcf940291e647aaa",
    "d90307a84fbea27778f280533cc9f554",
    "b3060e509e7c44eff1e401a67993eaa8",
    "660c1ca03df988dee2c8024cf327d450",
    "cd1838407bf211bdc4910498e64fa9a0",
    "9b307180f7e4227a89230831cc9e5240",
    "3761e301eec845f513471063993da480",
    "6fc3c602dc918aea268e20c7337b4801",
    "df878d04b92315d44d1d418f67f79002",
    "bf0f1b0872472aa99a3a821fcfee2104",
    "7e1e3610e58e55523575053e9fdc4308",
    "fd3c6d20ca1daaa46beb0a7d3fb98610",
    "fa79db41953a5448d7d614fb7f720d20",
    "f4f3b7822b75a890afad28f6ffe51a41",
    "e8e66e0557eb50215e5a51ecfeca3482",
]
RCON = [bytes.fromhex(x) for x in RCON_HEX]


def gf_mul(a: int, b: int) -> int:
    result = 0
    for _ in range(8):
        if b & 1:
            result ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return result


def gf_pow(a: int, exponent: int) -> int:
    result = 1
    while exponent:
        if exponent & 1:
            result = gf_mul(result, a)
        a = gf_mul(a, a)
        exponent >>= 1
    return result


def make_sbox() -> list[int]:
    box = []
    for x in range(256):
        inv = 0 if x == 0 else gf_pow(x, 254)
        y = inv
        for shift in range(1, 5):
            y ^= ((inv << shift) | (inv >> (8 - shift))) & 0xFF
        box.append(y ^ 0x63)
    return box


SBOX = make_sbox()
INV_SBOX = [0] * 256
for i, value in enumerate(SBOX):
    INV_SBOX[value] = i


def shift_rows(lane: bytes) -> bytes:
    out = bytearray(16)
    for row in range(4):
        for col in range(4):
            out[row + 4 * col] = lane[row + 4 * ((col + row) % 4)]
    return bytes(out)


def inv_shift_rows(lane: bytes) -> bytes:
    out = bytearray(16)
    for row in range(4):
        for col in range(4):
            out[row + 4 * ((col + row) % 4)] = lane[row + 4 * col]
    return bytes(out)


def mix_columns(lane: bytes) -> bytes:
    out = bytearray(16)
    for col in range(4):
        a0, a1, a2, a3 = lane[4 * col : 4 * col + 4]
        out[4 * col + 0] = gf_mul(a0, 2) ^ gf_mul(a1, 3) ^ a2 ^ a3
        out[4 * col + 1] = a0 ^ gf_mul(a1, 2) ^ gf_mul(a2, 3) ^ a3
        out[4 * col + 2] = a0 ^ a1 ^ gf_mul(a2, 2) ^ gf_mul(a3, 3)
        out[4 * col + 3] = gf_mul(a0, 3) ^ a1 ^ a2 ^ gf_mul(a3, 2)
    return bytes(out)


def inv_mix_columns(lane: bytes) -> bytes:
    out = bytearray(16)
    for col in range(4):
        a0, a1, a2, a3 = lane[4 * col : 4 * col + 4]
        out[4 * col + 0] = gf_mul(a0, 14) ^ gf_mul(a1, 11) ^ gf_mul(a2, 13) ^ gf_mul(a3, 9)
        out[4 * col + 1] = gf_mul(a0, 9) ^ gf_mul(a1, 14) ^ gf_mul(a2, 11) ^ gf_mul(a3, 13)
        out[4 * col + 2] = gf_mul(a0, 13) ^ gf_mul(a1, 9) ^ gf_mul(a2, 14) ^ gf_mul(a3, 11)
        out[4 * col + 3] = gf_mul(a0, 11) ^ gf_mul(a1, 13) ^ gf_mul(a2, 9) ^ gf_mul(a3, 14)
    return bytes(out)


def aes_round_keyless(lane: bytes) -> bytes:
    return mix_columns(shift_rows(bytes(SBOX[x] for x in lane)))


def aes_round_keyless_inv(lane: bytes) -> bytes:
    return bytes(INV_SBOX[x] for x in inv_shift_rows(inv_mix_columns(lane)))


def xor_bytes(left: bytes, right: bytes) -> bytes:
    assert len(left) == len(right)
    return bytes(a ^ b for a, b in zip(left, right))


def apply_mix(state: bytes, table: list[list[int]]) -> bytes:
    flat = [x for row in table for x in row]
    assert len(state) == len(flat)
    return bytes(state[source] for source in flat)


def apply_mix_inverse(state: bytes, table: list[list[int]]) -> bytes:
    flat = [x for row in table for x in row]
    inverse = [0] * len(flat)
    for output, source in enumerate(flat):
        inverse[source] = output
    return bytes(state[source] for source in inverse)


@dataclass(frozen=True)
class Variant:
    name: str
    n: int
    lanes: int
    steps: int
    rate_bytes: int
    capacity_bytes: int
    mix: tuple[tuple[int, ...], ...]


def variant(name: str) -> Variant:
    p = PARAMS[name]
    table = MIX_1024 if p["lanes"] == 8 else MIX_2048
    return Variant(
        name=name,
        n=p["n"],
        lanes=p["lanes"],
        steps=p["steps"],
        rate_bytes=p["rate"] // 8,
        capacity_bytes=p["capacity"] // 8,
        mix=tuple(tuple(row) for row in table),
    )


def wish_permutation(state: bytes, tweak: bytes, v: Variant) -> bytes:
    assert len(state) == v.n // 8
    assert len(tweak) == 16
    lanes = [state[16 * i : 16 * (i + 1)] for i in range(v.lanes)]
    table = [index for row in v.mix for index in row]
    first_capacity_lane = v.lanes // 2
    for step in range(v.steps):
        lanes[first_capacity_lane] = xor_bytes(lanes[first_capacity_lane], tweak)
        lanes = [aes_round_keyless(lane) for lane in lanes]
        lanes[0] = xor_bytes(lanes[0], RCON[2 * step])
        lanes = [aes_round_keyless(lane) for lane in lanes]
        lanes[0] = xor_bytes(lanes[0], RCON[2 * step + 1])
        state = b"".join(lanes)
        lanes = [apply_mix(state, v.mix)[16 * i : 16 * (i + 1)] for i in range(v.lanes)]
    return b"".join(lanes)


def wish_permutation_inverse(state: bytes, tweak: bytes, v: Variant) -> bytes:
    assert len(state) == v.n // 8
    assert len(tweak) == 16
    lanes = [state[16 * i : 16 * (i + 1)] for i in range(v.lanes)]
    first_capacity_lane = v.lanes // 2
    for step in reversed(range(v.steps)):
        state = b"".join(lanes)
        lanes = [apply_mix_inverse(state, v.mix)[16 * i : 16 * (i + 1)] for i in range(v.lanes)]
        lanes[0] = xor_bytes(lanes[0], RCON[2 * step + 1])
        lanes = [aes_round_keyless_inv(lane) for lane in lanes]
        lanes[0] = xor_bytes(lanes[0], RCON[2 * step])
        lanes = [aes_round_keyless_inv(lane) for lane in lanes]
        lanes[first_capacity_lane] = xor_bytes(lanes[first_capacity_lane], tweak)
    return b"".join(lanes)


def pad_10_star(message: bytes, rate_bytes: int) -> list[bytes]:
    # Since rate_bytes is integral, byte-aligned messages receive 0x80 followed
    # by the least number of zero bytes making a strictly larger rate multiple.
    padded_length = rate_bytes * (len(message) // rate_bytes + 1)
    padded = message + b"\x80" + b"\x00" * (padded_length - len(message) - 1)
    return [padded[i : i + rate_bytes] for i in range(0, len(padded), rate_bytes)]


def theta_value(capacity_bytes: int, reading: str) -> bytes:
    if reading == "section-3.4":
        # 0^(c-1)||1, with the last canonical array byte equal to 1.
        return b"\x00" * (capacity_bytes - 1) + b"\x01"
    if reading == "algorithm-2":
        # 1^c.
        return b"\xff" * capacity_bytes
    raise ValueError(reading)


def wish_hash(message: bytes, variant_name: str, theta_reading: str) -> bytes:
    v = variant(variant_name)
    blocks = pad_10_star(message, v.rate_bytes)
    rate = b"\x00" * v.rate_bytes
    capacity = b"\x00" * v.capacity_bytes
    theta = theta_value(v.capacity_bytes, theta_reading)
    for i, block in enumerate(blocks):
        tweak = i.to_bytes(8, "big") + b"\x00" * 8
        rate = xor_bytes(rate, block)
        if i == len(blocks) - 1:
            capacity = xor_bytes(capacity, theta)
        feed_forward = capacity
        permuted = wish_permutation(rate + capacity, tweak, v)
        out_rate = permuted[: v.rate_bytes]
        out_capacity = permuted[v.rate_bytes :]
        rate = xor_bytes(out_rate, b"\x00" * v.rate_bytes)
        capacity = xor_bytes(out_capacity, feed_forward)
    return capacity


def lfsr_word(word: bytes) -> bytes:
    out = bytearray(16)
    for i, x in enumerate(word):
        out[i] = ((x << 1) & 0xFE) | (((x >> 7) & 1) ^ ((x >> 5) & 1))
    return bytes(out)


def audit_tables() -> dict[str, object]:
    result: dict[str, object] = {
        "sbox_bijection": len(set(SBOX)) == 256,
        "sbox_inverse": all(INV_SBOX[SBOX[x]] == x for x in range(256)),
        "sbox_known_values": {
            "00": f"{SBOX[0]:02x}",
            "53": f"{SBOX[0x53]:02x}",
            "ff": f"{SBOX[0xFF]:02x}",
        },
        "aes_mix_known_vector": mix_columns(bytes.fromhex("db135345" + "00" * 12))[:4].hex(),
        "rcon_generated_matches_printed": [lfsr_word(RCON[i - 1]).hex() == RCON_HEX[i] for i in range(1, 24)],
    }
    for v in (variant("Wish-512"), variant("Wish-1024")):
        flat = [x for row in v.mix for x in row]
        inverse = [0] * len(flat)
        for output, source in enumerate(flat):
            inverse[source] = output
        lane_count = v.lanes
        truncated_half = set(range(v.n // 16, v.n // 8))

        def spread(indices: Iterable[int]) -> dict[str, object]:
            idx = list(indices)
            lane_bal = all(
                sum(
                    1
                    for source in idx[16 * output_lane : 16 * (output_lane + 1)]
                    if source // 16 == input_lane
                )
                == (2 if lane_count == 8 else 1)
                for output_lane in range(lane_count)
                for input_lane in range(lane_count)
            )
            col_spread = all(
                len({source // 4 for source in idx[4 * col : 4 * col + 4]}) == 4
                for col in range(len(idx) // 4)
            )
            col_control = all(
                len({source // 16 for source in idx[4 * col : 4 * col + 4]}) >= 2
                for col in range(len(idx) // 4)
            )
            return {
                "balanced_lane_spread": lane_bal,
                "balanced_column_spread": col_spread,
                "balanced_column_control": col_control,
            }

        # ShiftRows acts independently inside each post-Mix lane.
        shifted = []
        for output in range(len(flat)):
            lane = output // 16
            row = output % 4
            col = (output // 4) % 4
            source_col = (col + row) % 4
            shifted.append(flat[16 * lane + 4 * source_col + row])

        result[v.name] = {
            "table_bijection": sorted(flat) == list(range(v.n // 8)),
            "direct": spread(flat),
            "inverse": spread(inverse),
            "shiftrows_composed": spread(shifted),
            "truncation_counts_inverse_output_columns": [
                sum(1 for source in inverse[4 * col : 4 * col + 4] if source in truncated_half)
                for col in range(len(inverse) // 4)
            ],
        }
        roundtrips = []
        for seed in range(4):
            trial_state = bytes(
                ((37 + 11 * seed) * i + 19 + seed) & 0xFF
                for i in range(v.n // 8)
            )
            trial_tweak = bytes(
                ((53 + 7 * seed) * i + 7 + 13 * seed) & 0xFF
                for i in range(16)
            )
            permuted = wish_permutation(trial_state, trial_tweak, v)
            roundtrips.append(
                wish_permutation_inverse(permuted, trial_tweak, v) == trial_state
            )
        result[v.name]["full_permutation_roundtrips_passed"] = roundtrips
    return result


def test_messages(rate_bytes: int) -> list[tuple[str, bytes]]:
    return [
        ("empty", b""),
        ("one-zero-byte", b"\x00"),
        ("abc", b"abc"),
        ("rate-minus-1", bytes(range(rate_bytes - 1))),
        ("rate-exact", bytes(range(rate_bytes))),
        ("rate-plus-1", bytes(range(rate_bytes)) + b"\x80"),
        ("three-blocks", bytes((i * 37 + 11) & 0xFF for i in range(2 * rate_bytes + 5))),
    ]


def compare_outputs() -> list[dict[str, object]]:
    rows = []
    for name in PARAMS:
        rate_bytes = PARAMS[name]["rate"] // 8
        for label, message in test_messages(rate_bytes):
            section = wish_hash(message, name, "section-3.4")
            algorithm = wish_hash(message, name, "algorithm-2")
            xor = xor_bytes(section, algorithm)
            rows.append(
                {
                    "variant": name,
                    "case": label,
                    "message_hex": message.hex(),
                    "message_bits": len(message) * 8,
                    "section_3_4_digest": section.hex(),
                    "algorithm_2_digest": algorithm.hex(),
                    "differ": section != algorithm,
                    "xor_hex": xor.hex(),
                    "hamming_distance_bits": sum(x.bit_count() for x in xor),
                }
            )
    return rows


def main() -> None:
    report = {
        "source": {
            "path": "hash-35-spec.pdf",
            "sha256": hashlib.sha256(open("hash-35-spec.pdf", "rb").read()).hexdigest(),
        },
        "scope": "byte-aligned messages, independent exploratory implementation",
        "audit": audit_tables(),
        "comparisons": compare_outputs(),
    }
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
