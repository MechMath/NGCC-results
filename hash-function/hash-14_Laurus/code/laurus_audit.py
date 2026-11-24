#!/usr/bin/env python3
"""Independent executable audit of the Laurus specification.

Input source:
  https://cdn.jsdelivr.net/gh/ngcc-dev/ngcc-harness@dc66c6cb3c06e75bdea0048e21fa4e13c63f00af/hash-14/hash-14-spec.pdf
  sha256 63190edaf6bd2b85c93f21f49412567cfcb0c8330063c9124d19cd64cd91b141

The implementation follows the specification's MSB-left bit numbering and
big-endian byte order.  It is an audit reference implementation, not production
cryptographic code.
"""

from __future__ import annotations

import hashlib
import json
import sys


MASK64 = (1 << 64) - 1
RC = [
    0xB7E151628AED2A6A,
    0xAF82A3CD15DAD4D7,
    0x9F4546922BB529AD,
    0xFECA8C2C576AD359,
    0x3DD51950AED526B1,
    0x7BAA32A15DAA4D62,
    0xF7546542BB549AC4,
    0x2EE8CB8D76A9B58B,
    0x5DD1971AED536B16,
    0xBBA32E35DAA6D62C,
    0xB7065D63B54D2C5B,
    0xAE4CBBCF6A9AD8B5,
    0x9CD97696D5353169,
    0xF9F2EC25AA6AE2D1,
    0x33A5D94354D545A1,
    0x674BB286A9AA8B42,
]

SBOX = [
    0, 2, 4, 23, 8, 10, 14, 13, 16, 18, 20, 15, 28, 30, 26, 17,
    1, 19, 5, 6, 9, 27, 31, 12, 25, 11, 29, 22, 21, 7, 3, 24,
]

THETA_PARAMS = [
    (31, 1, 4, 21, 22),
    (19, 12, 15, 34, 13),
    (28, 35, 58, 9, 23),
    (55, 18, 5, 27, 44),
    (14, 43, 53, 20, 25),
]


def rotl64(value: int, count: int) -> int:
    count %= 64
    value &= MASK64
    return ((value << count) | (value >> (64 - count))) & MASK64 if count else value


def rotr64(value: int, count: int) -> int:
    count %= 64
    value &= MASK64
    return ((value >> count) | (value << (64 - count))) & MASK64 if count else value


def get_msb(value: int, length: int, count: int) -> int:
    return (value >> (length - count)) & ((1 << count) - 1)


def get_lsb(value: int, count: int) -> int:
    return value & ((1 << count) - 1)


def xor_words(words) -> int:
    out = 0
    for word in words:
        out ^= word
    return out


def state_from_int(value: int):
    if not 0 <= value < (1 << 1600):
        raise ValueError("state outside [0, 2^1600)")
    return [
        [(value >> (1600 - 64 * (5 * i + j + 1))) & MASK64 for j in range(5)]
        for i in range(5)
    ]


def state_to_int(state) -> int:
    value = 0
    for i in range(5):
        for j in range(5):
            value = (value << 64) | (state[i][j] & MASK64)
    return value


def iota(state, round_index: int):
    out = [row[:] for row in state]
    out[0][0] ^= RC[round_index]
    return out


def chi_formula(state):
    out = [[0] * 5 for _ in range(5)]
    for lane in range(5):
        a0, a1, a2, a3, a4 = (state[i][lane] for i in range(5))
        out[0][lane] = (
            (a0 & a2 & a3)
            ^ (a2 & a3 & a4)
            ^ (a0 & a4)
            ^ (a3 & a4)
            ^ a1
        )
        out[1][lane] = (a1 & a3 & a4) ^ (a0 & a1) ^ a2
        out[2][lane] = (a1 & a2) ^ a3
        out[3][lane] = (a2 & a3) ^ a4
        out[4][lane] = (a3 & a4) ^ a0
    return out


def chi_optimized(state):
    out = [[0] * 5 for _ in range(5)]
    for lane in range(5):
        a0, a1, a2, a3, a4 = (state[i][lane] for i in range(5))
        b4 = (a3 & a4) ^ a0
        b3 = (a2 & a3) ^ a4
        b2 = (a1 & a2) ^ a3
        b1 = (b4 & a1) ^ a2
        b0 = (b4 & b3) ^ a1
        for i, bit in enumerate((b0, b1, b2, b3, b4)):
            out[i][lane] = bit
    return out


def sbox_formula_msb(x: int) -> int:
    """Section 2.3 formula, with A[0] the MSB of x."""
    state = [[0] * 64 for _ in range(5)]
    for lane in range(64):
        state[0][lane] = (x >> 4) & 1
        state[1][lane] = (x >> 3) & 1
        state[2][lane] = (x >> 2) & 1
        state[3][lane] = (x >> 1) & 1
        state[4][lane] = x & 1
    out = chi_formula(state)
    y = 0
    for i in range(5):
        y = (y << 1) | out[i][0]
    return y


def theta_plane(plane, params):
    e = xor_words(plane)
    f = xor_words(rotl64(plane[i], params[i]) for i in range(5))
    return [plane[i] ^ rotr64(e, params[i]) ^ f for i in range(5)]


def theta(state):
    return [theta_plane(state[i], THETA_PARAMS[i]) for i in range(5)]


def pi_explicit(state):
    """PDF 2.3: B[i][j] = A[(i+2j) mod 5][(3i+3j) mod 5]."""
    return [
        [state[(i + 2 * j) % 5][(3 * i + 3 * j) % 5] for j in range(5)]
        for i in range(5)
    ]


def pi_optimized(state):
    """PDF 5.2: B[(4i+4j) mod 5][(i+3j) mod 5] = A[i][j]."""
    out = [[None] * 5 for _ in range(5)]
    for i in range(5):
        for j in range(5):
            out[(4 * i + 4 * j) % 5][(i + 3 * j) % 5] = state[i][j]
    return out


def pi_section_3_property_2(state):
    """Alternate reading: apply M^-1=(1,2;3,3) forward to input coordinates."""
    return [
        [state[(4 * i + 4 * j) % 5][(i + 3 * j) % 5] for j in range(5)]
        for i in range(5)
    ]


def permutation(value: int, pi_impl=pi_explicit, rounds: int = 16) -> int:
    state = state_from_int(value)
    for r in range(rounds):
        state = pi_impl(theta(chi_formula(iota(state, r))))
    return state_to_int(state)


def gf5_permutation_audit():
    names = []
    for i in range(5):
        for j in range(5):
            names.append((i, j))
    explicit = [names.index(((i + 2 * j) % 5, (3 * i + 3 * j) % 5)) for i, j in names]
    optimized = [None] * 25
    for i in range(5):
        for j in range(5):
            optimized[names.index(((4 * i + 4 * j) % 5, (i + 3 * j) % 5))] = names.index((i, j))
    alt = [names.index(((4 * i + 4 * j) % 5, (i + 3 * j) % 5)) for i, j in names]

    def matmul(a, b):
        return [
            [(a[0][0] * b[0][0] + a[0][1] * b[1][0]) % 5,
             (a[0][0] * b[0][1] + a[0][1] * b[1][1]) % 5],
            [(a[1][0] * b[0][0] + a[1][1] * b[1][0]) % 5,
             (a[1][0] * b[0][1] + a[1][1] * b[1][1]) % 5],
        ]

    m = [[4, 4], [1, 3]]
    inverse = [[1, 2], [3, 3]]
    order = 1
    power = m
    while power != [[1, 0], [0, 1]]:
        power = matmul(power, m)
        order += 1
    return {
        "explicit_equals_optimized": explicit == optimized,
        "forward_M_equals_explicit": alt == explicit,
        "M_times_inverse": matmul(m, inverse),
        "M_order": order,
        "explicit_permutation": explicit,
        "section_3_property_2_permutation": alt,
    }


def gaussian_rank(rows):
    basis = {}
    for value in rows:
        while value:
            pivot = value.bit_length() - 1
            if pivot not in basis:
                basis[pivot] = value
                break
            value ^= basis[pivot]
    return len(basis)


def theta_audit():
    maps = []
    for plane_index, params in enumerate(THETA_PARAMS):
        rows = []
        for bit in range(320):
            source = [0] * 5
            source[bit // 64] = 1 << (bit % 64)
            target = theta_plane(source, params)
            rows.append(sum(word << (64 * i) for i, word in enumerate(target)))
        maps.append({
            "plane": plane_index,
            "params": params,
            "rank": gaussian_rank(rows),
            "full_rank": gaussian_rank(rows) == 320,
        })
    parameter_failures = []
    for plane, params in enumerate(THETA_PARAMS):
        if len({(2 * t) % 64 for t in params}) != 5:
            parameter_failures.append({"plane": plane, "condition": 1})
        for i in range(5):
            for j in range(5):
                if (params[i] + params[j]) % 64 == 0:
                    parameter_failures.append({"plane": plane, "condition": 2, "i": i, "j": j})
        for i in range(5):
            for j in range(5):
                for k in range(5):
                    if len({i, j, k}) == 3 and (params[i] + params[j] - 2 * params[k]) % 64 == 0:
                        parameter_failures.append(
                            {"plane": plane, "condition": 3, "i": i, "j": j, "k": k}
                        )
        for i in range(5):
            for j in range(i + 1, 5):
                for k in range(5):
                    for ell in range(k + 1, 5):
                        if len({i, j, k, ell}) == 4 and (
                            params[i] + params[j] - params[k] - params[ell]
                        ) % 64 == 0:
                            parameter_failures.append(
                                {"plane": plane, "condition": 4, "pair1": [i, j], "pair2": [k, ell]}
                            )
    return {"maps": maps, "parameter_failures": parameter_failures}


def pad(message: int, bit_length: int, c: int):
    r = 1536 - c
    delta = (bit_length - 512) % r
    if bit_length == 0 or delta != 0:
        zeros = r - 1 - delta
        padded = (message << (1 + zeros)) | (1 << zeros)
        padded_length = bit_length + 1 + zeros
    else:
        padded_length = bit_length
        padded = message
    if padded_length < 512:
        padded <<= 512 - padded_length
        padded_length = 512
    block_count = max(0, (bit_length - 512 + r - 1) // r) if bit_length else 0
    expected = 512 + block_count * r
    if padded_length != expected:
        raise AssertionError((bit_length, padded_length, expected))
    return padded, padded_length


def g0(message: int, message_bits: int, state: int) -> int:
    x = (message << 1536) | state
    length = message_bits + 1536
    return (get_msb(x, length, 1536) << 1536) | (
        (get_lsb(x, 1024) << 512) | get_msb(x, length, 512)
    )


def g1(state: int, final_message: int) -> int:
    x = (state << 512) | final_message
    return (get_lsb(x, 1536) << 1088) | get_lsb(x, 1088)


def laurus(message: bytes, bit_length: int, c: int, fid: int, output_bits: int,
           pi_impl=pi_explicit):
    if not 0 <= bit_length <= len(message) * 8:
        raise ValueError("invalid bit length")
    if len(message) * 8 - bit_length >= 8:
        raise ValueError("the unused suffix must be less than one byte")
    message_int = int.from_bytes(message, "big")
    if len(message) * 8 > bit_length:
        message_int >>= len(message) * 8 - bit_length
    padded, padded_length = pad(message_int, bit_length, c)
    r = 1536 - c
    block_count = padded_length // r if padded_length > 512 else 0
    blocks = []
    shift = padded_length
    for _ in range(block_count):
        shift -= r
        blocks.append(((padded >> shift) & ((1 << r) - 1), r))
    final_message = padded & ((1 << 512) - 1)

    state = (1 << 63) * fid + c
    for index, (block, block_bits) in enumerate(blocks, start=1):
        packed = g0(block, block_bits, state)
        counter = (index - 1) << 1536
        mixed = permutation(counter | get_msb(packed, 3072, 1536), pi_impl)
        state = get_lsb(mixed, 1536) ^ get_lsb(packed, 1536)

    d = 1 if bit_length and (bit_length - 512) % r == 0 else 0
    packed = g1(state, final_message)
    result = 0
    result_bits = 0
    index = 0
    while result_bits < output_bits:
        counter = (1 << 63) | (d << 62) | index
        mixed = permutation(counter | get_msb(packed, 2624, 1536), pi_impl)
        block = get_lsb(mixed, 1088) ^ get_lsb(packed, 1088)
        result = (result << 1088) | block
        result_bits += 1088
        index += 1
    result >>= result_bits - output_bits
    return result.to_bytes((output_bits + 7) // 8, "big"), {
        "padded_bits": padded_length,
        "absorbed_r_blocks": block_count,
        "d": d,
        "squeeze_blocks": index,
    }


def hexbits(value: int, bits: int) -> str:
    return value.to_bytes((bits + 7) // 8, "big").hex()


def main():
    sbox_rows = [sbox_formula_msb(x) for x in range(32)]
    pi_result = gf5_permutation_audit()
    theta_result = theta_audit()

    random_state = int.from_bytes(hashlib.sha256(b"laurus-audit-state").digest(), "big")
    random_state = (random_state << 1184) & ((1 << 1600) - 1)
    state = state_from_int(random_state)
    chi_formula_equals_optimized = all(
        chi_formula([[(lane >> b) & 1 for lane in row] for row in state])
        == chi_optimized([[(lane >> b) & 1 for lane in row] for row in state])
        for b in range(64)
    )

    boundary_lengths = [0, 1, 511, 512, 513, 1535, 1536, 1537, 2559, 2560, 2561]
    padding = {}
    for c in (512, 768, 1024):
        r = 1536 - c
        boundary_lengths.extend([512 + k * r - 1 for k in range(1, 4) if r == 512])
        boundary_lengths.extend([512 + k * r for k in range(1, 4)])
        boundary_lengths.extend([512 + k * r + 1 for k in range(1, 4)])
        padding[str(c)] = {}
        for length in sorted(set(boundary_lengths)):
            byte_length = (length + 7) // 8
            align = byte_length * 8 - length
            message = (int.from_bytes(hashlib.shake_128(f"pad-{length}".encode()).digest(byte_length), "big")
                       >> align)
            _, padded_length = pad(message, length, c)
            padding[str(c)][str(length)] = padded_length

    messages = [
        ("empty", b"", 0),
        ("abc", b"abc", 24),
        ("512zero", bytes(64), 512),
        ("513zero", bytes(64) + b"\x00", 513),
    ]
    profiles = []
    for name, message, bits in messages:
        for profile, c, fid, out_bits in (
            ("Laurus-512", 512, 0, 512),
            ("Laurus-768", 768, 0, 768),
            ("Laurus-1024", 1024, 0, 1024),
            ("Laurus-XOF-2048", 512, 1, 2048),
        ):
            explicit, trace = laurus(message, bits, c, fid, out_bits, pi_explicit)
            optimized, _ = laurus(message, bits, c, fid, out_bits, pi_optimized)
            alternate, _ = laurus(message, bits, c, fid, out_bits, pi_section_3_property_2)
            profiles.append({
                "message": name,
                "profile": profile,
                "output_bits": out_bits,
                "explicit_hex": explicit.hex(),
                "pi_explicit_equals_pi_optimized": explicit == optimized,
                "pi_explicit_equals_section_3_property_2_reading": explicit == alternate,
                "trace": trace,
            })

    report = {
        "source": {
            "url": "https://cdn.jsdelivr.net/gh/ngcc-dev/ngcc-harness@dc66c6cb3c06e75bdea0048e21fa4e13c63f00af/hash-14/hash-14-spec.pdf",
            "sha256": "63190edaf6bd2b85c93f21f49412567cfcb0c8330063c9124d19cd64cd91b141",
        },
        "environment": {
            "python": sys.version.split()[0],
            "implementation": "laurus_audit.py",
        },
        "sbox": {
            "table": SBOX,
            "formula_msb": sbox_rows,
            "matches_under_msb_first": sbox_rows == SBOX,
            "formula_lsb_first": [sbox_formula_msb(int(f"{x:05b}"[::-1], 2)) for x in range(32)],
        },
        "chi_formula_equals_optimized_on_state": chi_formula_equals_optimized,
        "pi": pi_result,
        "theta": theta_result,
        "padding": padding,
        "profiles": profiles,
    }
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
