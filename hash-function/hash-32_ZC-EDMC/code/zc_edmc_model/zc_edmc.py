#!/usr/bin/env python3
"""Bit-exact executable model of the ZC permutations and both ZC-EDMC readings.

Scope: PDF pages 5-15 of the allowlisted hash-32 specification.  The wire
serialization is stated explicitly because the specification defines the
leading/rate bits but does not define a byte or lane-serialization order.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import random
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


MASK64 = (1 << 64) - 1
ROUND_CONSTANTS = (
    0x0000000000000058,  # -11
    0x0000000000000038,  # -10
    0x00000000000003C0,  # -9
    0x00000000000000D0,  # -8
    0x0000000000000060,  # -7
    0x0000000000000120,  # -6
    0x0000000000000014,  # -5
    0x000000000000002C,  # -4
    0x00000000000000F0,  # -3
    0x00000000000001A0,  # -2
    0x0000000000000380,  # -1
    0x0000000000000012,  # 0
)


@dataclass(frozen=True)
class Profile:
    name: str
    m: int
    n: int
    c: int
    r: int
    r_prime: int
    width: int
    planes: int
    theta_shifts: tuple[int, int]
    rho_shifts: tuple[tuple[int, int], ...]

    def validate(self) -> None:
        if self.m != 64 * self.width * self.planes:
            raise ValueError(f"bad state size for {self.name}")
        if self.c != self.n + 64 or self.r != self.m - self.c:
            raise ValueError(f"bad capacity/rate relation for {self.name}")
        if self.r_prime != self.r:
            raise ValueError(f"bad squeezing rate for {self.name}")
        if len(self.rho_shifts) != self.planes:
            raise ValueError(f"bad rho table for {self.name}")


ZC1280 = Profile(
    name="ZC-1280",
    m=1280,
    n=512,
    c=576,
    r=704,
    r_prime=704,
    width=4,
    planes=5,
    theta_shifts=(5, 14),
    rho_shifts=((0, 0), (1, 5), (3, 24), (0, 1), (2, 3)),
)

ZC1536 = Profile(
    name="ZC-1536",
    m=1536,
    n=512,
    c=576,
    r=960,
    r_prime=960,
    width=8,
    planes=3,
    theta_shifts=(20, 56),
    rho_shifts=((0, 0), (3, 3), (5, 0)),
)

SUPPORTED_PROFILES = {
    ("ZC-1280", 1280, 512): ZC1280,
    ("ZC-1536", 1536, 512): ZC1536,
    ("ZC-1280", 1280, 768): Profile(
        "ZC-1280", 1280, 768, 832, 448, 448, 4, 5,
        (5, 14), ZC1280.rho_shifts,
    ),
    ("ZC-1536", 1536, 768): Profile(
        "ZC-1536", 1536, 768, 832, 704, 704, 8, 3,
        (20, 56), ZC1536.rho_shifts,
    ),
    ("ZC-1280", 1280, 1024): Profile(
        "ZC-1280", 1280, 1024, 1088, 192, 192, 4, 5,
        (5, 14), ZC1280.rho_shifts,
    ),
    ("ZC-1536", 1536, 1024): Profile(
        "ZC-1536", 1536, 1024, 1088, 448, 448, 8, 3,
        (20, 56), ZC1536.rho_shifts,
    ),
}

State = list[list[int]]
Reading = str


def rol64(value: int, amount: int) -> int:
    amount %= 64
    if amount == 0:
        return value & MASK64
    return ((value << amount) | (value >> (64 - amount))) & MASK64


def ror64(value: int, amount: int) -> int:
    return rol64(value, -amount)


def zero_state(profile: Profile) -> State:
    return [[0 for _ in range(profile.width)] for _ in range(profile.planes)]


def copy_state(state: State) -> State:
    return [row[:] for row in state]


def apply_rho(state: State, profile: Profile) -> State:
    out = copy_state(state)
    for y, (dx, dz) in enumerate(profile.rho_shifts):
        if y == 0:
            continue
        for x in range(profile.width):
            out[y][x] = rol64(state[y][(x - dx) % profile.width], dz)
    return out


def invert_rho(state: State, profile: Profile) -> State:
    out = copy_state(state)
    for y, (dx, dz) in enumerate(profile.rho_shifts):
        if y == 0:
            continue
        for x in range(profile.width):
            out[y][x] = ror64(state[y][(x + dx) % profile.width], dz)
    return out


def chi_column(values: tuple[int, ...]) -> tuple[int, ...]:
    size = len(values)
    return tuple(
        values[i] ^ ((1 - values[(i + 1) % size]) & values[(i + 2) % size])
        for i in range(size)
    )


CHI_TABLES: dict[int, dict[tuple[int, ...], tuple[int, ...]]] = {}
for _size in (3, 5):
    _table: dict[tuple[int, ...], tuple[int, ...]] = {}
    for _value in range(1 << _size):
        _column = tuple((_value >> i) & 1 for i in range(_size))
        _table[chi_column(_column)] = _column
    if len(_table) != (1 << _size):
        raise AssertionError("chi is not bijective")
    CHI_TABLES[_size] = _table


def invert_gf2_columns(columns: list[int]) -> list[int]:
    """Invert a 64-bit full-rank GF(2) map represented by output columns."""
    dimension = 64
    rows = []
    for row_index in range(dimension):
        coefficients = 0
        for column_index, column in enumerate(columns):
            coefficients |= ((column >> row_index) & 1) << column_index
        rows.append(coefficients | ((1 << row_index) << dimension))

    for column_index in range(dimension):
        pivot = next(
            (row for row in range(column_index, dimension)
             if (rows[row] >> column_index) & 1),
            None,
        )
        if pivot is None:
            raise ValueError("singular GF(2) matrix")
        rows[column_index], rows[pivot] = rows[pivot], rows[column_index]
        pivot_row = rows[column_index]
        for row in range(dimension):
            if row != column_index and ((rows[row] >> column_index) & 1):
                rows[row] ^= pivot_row

    inverse_columns = [0] * dimension
    for row in rows:
        coefficients = row & MASK64
        if coefficients == 0 or coefficients & (coefficients - 1):
            raise ValueError("matrix did not reduce to identity")
        column_index = coefficients.bit_length() - 1
        right_hand_side = row >> dimension
        for input_bit in range(dimension):
            if (right_hand_side >> input_bit) & 1:
                inverse_columns[input_bit] |= 1 << column_index
    return inverse_columns


def theta_shift(value: int, profile: Profile) -> int:
    return rol64(value, profile.theta_shifts[0]) ^ rol64(value, profile.theta_shifts[1])


def theta_inverse_map(profile: Profile) -> list[int]:
    """Precompute the inverse maps used by theta on the parity plane."""
    def shift_power(value: int, power: int) -> int:
        for _ in range(power):
            value = theta_shift(value, profile)
        return value

    columns = [
        (1 << bit) ^ shift_power(1 << bit, profile.width)
        for bit in range(64)
    ]
    return invert_gf2_columns(columns)


THETA_INVERSE_DATA = {
    (profile.width, profile.theta_shifts): theta_inverse_map(profile)
    for profile in {id(profile): profile for profile in SUPPORTED_PROFILES.values()}.values()
}


def gf2_apply(columns: list[int], value: int) -> int:
    output = 0
    index = 0
    while value:
        if value & 1:
            output ^= columns[index]
        value >>= 1
        index += 1
    return output


def apply_chi(state: State, profile: Profile) -> State:
    out = copy_state(state)
    for y in range(profile.planes):
        next_y = (y + 1) % profile.planes
        next2_y = (y + 2) % profile.planes
        for x in range(profile.width):
            out[y][x] = state[y][x] ^ ((~state[next_y][x]) & state[next2_y][x] & MASK64)
    return out


def invert_chi(state: State, profile: Profile) -> State:
    out = zero_state(profile)
    table = CHI_TABLES[profile.planes]
    for x in range(profile.width):
        for z in range(64):
            output = tuple((state[y][x] >> z) & 1 for y in range(profile.planes))
            source = table[output]
            for y, bit in enumerate(source):
                out[y][x] |= bit << z
    return out


def apply_theta(state: State, profile: Profile) -> State:
    parity = [0] * profile.width
    for y in range(profile.planes):
        for x in range(profile.width):
            parity[x] ^= state[y][x]
    dz1, dz2 = profile.theta_shifts
    effect = [
        rol64(parity[(x - 1) % profile.width], dz1)
        ^ rol64(parity[(x - 1) % profile.width], dz2)
        for x in range(profile.width)
    ]
    return [[state[y][x] ^ effect[x] for x in range(profile.width)]
            for y in range(profile.planes)]


def invert_theta(state: State, profile: Profile) -> State:
    """Invert theta; theta is not generally an involution."""
    theta_parity = [0] * profile.width
    for y in range(profile.planes):
        for x in range(profile.width):
            theta_parity[x] ^= state[y][x]

    inverse_columns = THETA_INVERSE_DATA[
        (profile.width, profile.theta_shifts)
    ]
    known_last = 0
    for x in range(1, profile.width):
        known_last = theta_parity[x] ^ theta_shift(known_last, profile)
    p_zero = gf2_apply(
        inverse_columns,
        theta_parity[0] ^ theta_shift(known_last, profile),
    )
    original_parity = [p_zero]
    for x in range(1, profile.width):
        original_parity.append(
            theta_parity[x] ^ theta_shift(original_parity[x - 1], profile)
        )

    dz1, dz2 = profile.theta_shifts
    effect = [
        rol64(original_parity[(x - 1) % profile.width], dz1)
        ^ rol64(original_parity[(x - 1) % profile.width], dz2)
        for x in range(profile.width)
    ]
    return [[state[y][x] ^ effect[x] for x in range(profile.width)]
            for y in range(profile.planes)]


def apply_iota(state: State, constant: int) -> State:
    out = copy_state(state)
    out[0][0] ^= constant
    return out


def zc_round(state: State, profile: Profile, round_index: int) -> State:
    """Apply iota, chi, rho, theta, rho for round_index in 0,...,11."""
    if not 0 <= round_index < 12:
        raise ValueError("round_index must index the 12 specified rounds")
    state = apply_iota(state, ROUND_CONSTANTS[round_index])
    state = apply_chi(state, profile)
    state = apply_rho(state, profile)
    state = apply_theta(state, profile)
    return apply_rho(state, profile)


def inverse_zc_round(state: State, profile: Profile, round_index: int) -> State:
    state = invert_rho(state, profile)
    state = invert_theta(state, profile)
    state = invert_rho(state, profile)
    state = invert_chi(state, profile)
    return apply_iota(state, ROUND_CONSTANTS[round_index])


def zc_permute(state: State, profile: Profile, start: int = 0, count: int = 12) -> State:
    if start < 0 or count < 0 or start + count > 12:
        raise ValueError("round interval must lie inside 0,...,11")
    out = copy_state(state)
    for round_index in range(start, start + count):
        out = zc_round(out, profile, round_index)
    return out


def zc_invert(state: State, profile: Profile, start: int = 0, count: int = 12) -> State:
    if start < 0 or count < 0 or start + count > 12:
        raise ValueError("round interval must lie inside 0,...,11")
    out = copy_state(state)
    for round_index in range(start + count - 1, start - 1, -1):
        out = inverse_zc_round(out, profile, round_index)
    return out


def lane_indices(profile: Profile, layout: str) -> list[tuple[int, int]]:
    if layout == "x":
        return [(x, y) for x in range(profile.width) for y in range(profile.planes)]
    if layout == "y":
        return [(x, y) for y in range(profile.planes) for x in range(profile.width)]
    raise ValueError(f"unknown layout {layout!r}")


def state_to_bits(state: State, profile: Profile, layout: str = "x") -> list[int]:
    """Serialize with an explicit x-major or y-major lane convention."""
    return [
        (state[y][x] >> z) & 1
        for x, y in lane_indices(profile, layout)
        for z in range(64)
    ]


def bits_to_state(bits: Iterable[int], profile: Profile, layout: str = "x") -> State:
    values = list(bits)
    if len(values) != profile.m:
        raise ValueError(f"expected {profile.m} state bits, got {len(values)}")
    state = zero_state(profile)
    offset = 0
    for x, y in lane_indices(profile, layout):
        for z in range(64):
            state[y][x] |= (values[offset] & 1) << z
            offset += 1
    return state


def bytes_to_bits(data: bytes) -> list[int]:
    return [(byte >> (7 - bit)) & 1 for byte in data for bit in range(8)]


def bits_to_bytes(bits: Iterable[int]) -> bytes:
    values = list(bits)
    if len(values) % 8:
        raise ValueError("bit string length is not a multiple of eight")
    return bytes(
        sum(values[offset + bit] << (7 - bit) for bit in range(8))
        for offset in range(0, len(values), 8)
    )


def pad_message(message: bytes, rate: int) -> list[int]:
    """Exact M || 01 || 1 || 0^j || 1 from Algorithm 3."""
    return pad_bits(bytes_to_bits(message), rate)


def pad_bits(original: list[int], rate: int) -> list[int]:
    """Pad an arbitrary bit string using Algorithm 3's exact formula."""
    length = len(original)
    j = (-(length + 4)) % rate
    padded = original + [0, 1] + [1] + [0] * j + [1]
    if len(padded) % rate:
        raise AssertionError("padding failed to reach a block boundary")
    return padded


def absorb_block(
    state: State,
    block: list[int],
    profile: Profile,
    layout: str = "x",
) -> State:
    if len(block) != profile.r:
        raise ValueError("bad rate block")
    return xor_state_bits(state, block, profile, layout)


def xor_state_bits(
    state: State,
    bits: list[int],
    profile: Profile,
    layout: str = "x",
    start: int = 0,
) -> State:
    out = copy_state(state)
    for offset, bit in enumerate(bits):
        if bit:
            bit_index = start + offset
            if layout == "x":
                x = bit_index // (64 * profile.planes)
                y = (bit_index % (64 * profile.planes)) // 64
            else:
                y = bit_index // (64 * profile.width)
                x = (bit_index % (64 * profile.width)) // 64
            z = bit_index % 64
            out[y][x] ^= 1 << z
    return out


def feed_forward_capacity(
    state: State,
    original: State,
    profile: Profile,
    layout: str = "x",
) -> State:
    """XOR 0^r || Xc into state under the chosen serialization."""
    if profile.r % 64:
        raise NotImplementedError("model serialization assumes rate is a lane multiple")
    original_capacity = state_to_bits(original, profile, layout)[profile.r:]
    return xor_state_bits(state, original_capacity, profile, layout, start=profile.r)


def absorption_F(
    state: State,
    profile: Profile,
    reading: Reading,
    layout: str = "x",
) -> State:
    if reading == "hh":
        first_h = zc_permute(state, profile, start=6, count=6)
        fed = feed_forward_capacity(first_h, state, profile, layout)
        return zc_permute(fed, profile, start=6, count=6)
    if reading == "hg":
        first_g = zc_permute(state, profile, start=0, count=6)
        fed = feed_forward_capacity(first_g, state, profile, layout)
        return zc_permute(fed, profile, start=6, count=6)
    raise ValueError(f"unknown reading {reading!r}")


def zc_edmc_bits(
    message: list[int],
    profile: Profile,
    reading: Reading,
    layout: str = "x",
) -> bytes:
    profile.validate()
    padded = pad_bits(message, profile.r)
    blocks = [
        padded[offset:offset + profile.r]
        for offset in range(0, len(padded), profile.r)
    ]
    state = absorb_block(zero_state(profile), blocks[0], profile, layout)
    for block in blocks[1:]:
        state = absorb_block(
            absorption_F(state, profile, reading, layout),
            block,
            profile,
            layout,
        )
    state = absorption_F(state, profile, reading, layout)

    output = state_to_bits(state, profile, layout)[:profile.r_prime]
    while len(output) < profile.n:
        state = zc_permute(state, profile)
        output.extend(state_to_bits(state, profile, layout)[:profile.r_prime])
    return bits_to_bytes(output[:profile.n])


def zc_edmc(
    message: bytes,
    profile: Profile,
    reading: Reading,
    layout: str = "x",
) -> bytes:
    return zc_edmc_bits(bytes_to_bits(message), profile, reading, layout)


def seeded_state(profile: Profile, seed: int) -> State:
    rng = random.Random(seed)
    return [[rng.getrandbits(64) for _ in range(profile.width)]
            for _ in range(profile.planes)]


def permutation_checks(profile: Profile, trials: int = 16) -> dict:
    round_checks = []
    for round_index in range(12):
        for trial in range(trials):
            state = seeded_state(profile, 100_000 * profile.m + 100 * round_index + trial)
            advanced = zc_round(state, profile, round_index)
            replay = inverse_zc_round(advanced, profile, round_index)
            if replay != state:
                raise AssertionError(
                    f"{profile.name} round {round_index} inverse failed at trial {trial}"
                )
        round_checks.append({"round_index": round_index, "trials": trials, "bijective": True})

    full_checks = []
    for trial in range(trials):
        state = seeded_state(profile, 200_000 * profile.m + trial)
        advanced = zc_permute(state, profile)
        replay = zc_invert(advanced, profile)
        if replay != state:
            raise AssertionError(f"{profile.name} full inverse failed at trial {trial}")
        full_checks.append({"trial": trial, "bijective": True})

    chi_checks = []
    for size in (profile.planes,):
        chi_checks.append({
            "width": size,
            "universe_size": 1 << size,
            "images": len(CHI_TABLES[size]),
            "bijective": len(CHI_TABLES[size]) == (1 << size),
        })
    return {
        "profile": profile.name,
        "round_checks": round_checks,
        "full_permutation_checks": full_checks,
        "chi_checks": chi_checks,
    }


def padding_checks(profile: Profile, max_bytes: int = 256) -> dict:
    multi_block = 0
    examples = []
    for length in range(max_bytes + 1):
        padded = pad_message(bytes(length), profile.r)
        if len(padded) % profile.r:
            raise AssertionError("padding boundary check failed")
        if len(padded) >= 2 * profile.r:
            multi_block += 1
        if length < 4:
            examples.append({
                "input_bits": 8 * length,
                "padded_bits": len(padded),
                "blocks": len(padded) // profile.r,
                "j": (-(8 * length + 4)) % profile.r,
            })
    if max_bytes < 256:
        raise ValueError("padding sweep too small")
    return {
        "checked_input_byte_lengths": [0, max_bytes],
        "checked_count": max_bytes + 1,
        "multi_block_cases": multi_block,
        "examples": examples,
    }


def zero_feed_control(profile: Profile) -> dict:
    """Check the stated special case where the padded block has zero capacity."""
    cases = []
    for label, message_bits in (
        ("empty", []),
        ("87_zero_bytes", [0] * (87 * 8)),
    ):
        padded = pad_bits(message_bits, profile.r)
        initial = absorb_block(zero_state(profile), padded, profile, "x")
        capacity_is_zero = not any(state_to_bits(initial, profile, "x")[profile.r:])
        g_six = zc_permute(initial, profile, start=0, count=6)
        h_six = zc_permute(initial, profile, start=6, count=6)
        g_fed = feed_forward_capacity(g_six, initial, profile, "x")
        h_fed = feed_forward_capacity(h_six, initial, profile, "x")
        f_hh = absorption_F(initial, profile, "hh", "x")
        f_hg = absorption_F(initial, profile, "hg", "x")
        difference_weight = sum(
            (f_hh[y][x] ^ f_hg[y][x]).bit_count()
            for y in range(profile.planes)
            for x in range(profile.width)
        )
        cases.append({
            "label": label,
            "capacity_is_zero": capacity_is_zero,
            "g_feed_is_copy": g_fed == g_six,
            "h_feed_is_copy": h_fed == h_six,
            "F_hh_vs_F_hg_full_state_difference_weight": difference_weight,
        })
    if not all(
        case["capacity_is_zero"]
        and case["g_feed_is_copy"]
        and case["h_feed_is_copy"]
        for case in cases
    ):
        raise AssertionError("zero-feed control failed")
    return {"profile": profile.name, "cases": cases}


def deterministic_short_search(profile: Profile, max_bits: int = 16) -> dict:
    count = 0
    for length in range(max_bits + 1):
        for value in range(1 << length):
            bits = [(value >> (length - 1 - i)) & 1 for i in range(length)]
            digest_hh = zc_edmc_bits(bits, profile, "hh")
            digest_hg = zc_edmc_bits(bits, profile, "hg")
            count += 1
            if digest_hh != digest_hg:
                return {
                    "search_order": (
                        "increasing bit length over all bit strings, then lexicographic "
                        "order where 0<1"
                    ),
                    "max_bits": max_bits,
                    "candidates_tested": count,
                    "first_difference": {
                        "message_bits_logical": length,
                        "message_bits": "".join(map(str, bits)),
                        "message_hex_left_aligned": bits_to_bytes(
                            bits + [0] * ((-length) % 8)
                        ).hex(),
                        "digest_hh_hex": digest_hh.hex(),
                        "digest_hg_hex": digest_hg.hex(),
                    },
                }
    return {
        "max_bits": max_bits,
        "candidates_tested": count,
        "first_difference": None,
    }


def source_digest_provenance() -> dict:
    root = Path(__file__).resolve().parent
    pdf = root / "input" / "hash-32-spec.pdf"
    extracted = root / "input" / "pages-05-15.txt"
    return {
        "source_url": (
            "https://cdn.jsdelivr.net/gh/ngcc-dev/ngcc-harness@"
            "dc66c6cb3c06e75bdea0048e21fa4e13c63f00af/hash-32/hash-32-spec.pdf"
        ),
        "pdf_path": str(pdf.relative_to(root.parent)),
        "pdf_sha256": hashlib.sha256(pdf.read_bytes()).hexdigest(),
        "extracted_pages_path": str(extracted.relative_to(root.parent)),
        "extracted_pages_sha256": hashlib.sha256(extracted.read_bytes()).hexdigest(),
    }


def run_all() -> dict:
    recommended = SUPPORTED_PROFILES[("ZC-1280", 1280, 512)]
    for profile in SUPPORTED_PROFILES.values():
        profile.validate()

    vectors = []
    for label, message_bits in (
        ("empty", []),
        ("one_bit_0", [0]),
        ("one_bit_1", [1]),
        ("one_byte_00", [0] * 8),
        ("one_byte_a5", bytes_to_bits(bytes.fromhex("a5"))),
        ("short_random_5_bytes", bytes_to_bits(bytes.fromhex("00a5c31e7b"))),
    ):
        aligned = message_bits + [0] * ((-len(message_bits)) % 8)
        vectors.append({
            "label": label,
            "message_bits_logical": len(message_bits),
            "message_hex_left_aligned": bits_to_bytes(aligned).hex(),
            "digest_hh_hex": zc_edmc_bits(message_bits, recommended, "hh").hex(),
            "digest_hg_hex": zc_edmc_bits(message_bits, recommended, "hg").hex(),
        })

    result = {
        "schema_version": 1,
        "status": "executable model and deterministic local checks; not crypto_run evidence",
        "environment": {
            "python": sys.version.split()[0],
            "platform": platform.platform(),
            "executable": sys.executable,
        },
        "source": source_digest_provenance(),
        "model_conventions": {
            "round_index": "0..11 denotes i=-11..0",
            "round_order": "iota, chi, rho1, theta, rho2",
            "rotation": "left cyclic x shift and left cyclic 64-bit z shift",
            "round_constant_placement": "bit z=0 is the LSB of A[0][0]",
            "state_serialization": "y-major, x-major, z=0..63; input byte bits MSB-first",
            "capacity_feed_forward": "xor original trailing c bits into the trailing c state bits",
            "F_hh": "h(h(X) xor (0^r||X_c))",
            "F_hg": "h(g(X) xor (0^r||X_c))",
        },
        "source_ambiguities": [
            {
                "id": "absorption_F",
                "detail": (
                    "Page 13 displays h(h(X) xor (...)); its adjacent prose and page 15 "
                    "Algorithm 3 say h(g(X) xor (...)). Both readings are implemented."
                ),
            },
            {
                "id": "wire_serialization",
                "detail": (
                    "Leading/trailing state bits and z=0 as the lane LSB are specified, but "
                    "no unique flattening of (x,y,z) bits into message bytes or digest bytes "
                    "is supplied. This model uses y-major, x-major, z-major and MSB-first bytes."
                ),
            },
            {
                "id": "padding_prose",
                "detail": (
                    "Page 13 says at least two padding bits are appended, but M||01 followed "
                    "by 1||0^j||1 appends at least four bits. The explicit Algorithm 3 formula "
                    "is implemented."
                ),
            },
        ],
        "profiles": {
            "recommended": {
                "name": recommended.name,
                "m": recommended.m,
                "n": recommended.n,
                "c": recommended.c,
                "r": recommended.r,
                "r_prime": recommended.r_prime,
            },
            "supported_profile_count": len(SUPPORTED_PROFILES),
        },
        "all_supported_profiles_smoke": [
            {
                "m": profile.m,
                "n": profile.n,
                "c": profile.c,
                "r": profile.r,
                "both_readings_return_n_bits": all(
                    len(zc_edmc_bits([], profile, reading, "x")) * 8 == profile.n
                    for reading in ("hh", "hg")
                ),
            }
            for _, profile in sorted(SUPPORTED_PROFILES.items())
        ],
        "permutation_checks": [
            permutation_checks(SUPPORTED_PROFILES[("ZC-1280", 1280, 512)]),
            permutation_checks(SUPPORTED_PROFILES[("ZC-1536", 1536, 512)]),
        ],
        "padding_checks": padding_checks(recommended),
        "zero_feed_control": zero_feed_control(recommended),
        "vectors_recommended_profile": vectors,
        "short_input_search_f_hh_vs_f_hg": deterministic_short_search(recommended),
        "interpretation_limits": (
            "These are deterministic local implementation checks. They establish the model's "
            "behaviour and formula divergence at the listed inputs only; they do not establish "
            "hash security, collision/preimage resistance, or a universal claim over messages."
        ),
    }
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        type=Path,
        help="write JSON evidence here; default is stdout",
    )
    args = parser.parse_args()
    result = run_all()
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
        print(f"wrote {args.output}")
    else:
        print(rendered, end="")


if __name__ == "__main__":
    main()
