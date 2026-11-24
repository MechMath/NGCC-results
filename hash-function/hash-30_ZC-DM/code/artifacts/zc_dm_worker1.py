#!/usr/bin/env python3
"""Independent, literal ZC-DM reference implementation from hash-30-spec.pdf.

The state is stored as A[y][x], where y indexes planes and x indexes 64-bit
lanes. Bit z is bit z (LSB=0) of the lane integer. This is the indexing in
Section 1.1 and Figure 1.1/1.2 of the allowlisted specification.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
import hashlib
import json
from pathlib import Path
import random
import sys

MASK64 = (1 << 64) - 1

ROUND_CONSTANTS = {
    -11: 0x0000000000000058,
    -10: 0x0000000000000038,
    -9: 0x00000000000003C0,
    -8: 0x00000000000000D0,
    -7: 0x0000000000000060,
    -6: 0x0000000000000120,
    -5: 0x0000000000000014,
    -4: 0x000000000000002C,
    -3: 0x00000000000000F0,
    -2: 0x00000000000001A0,
    -1: 0x0000000000000380,
    0: 0x0000000000000012,
}


@dataclass(frozen=True)
class Variant:
    name: str
    nx: int
    ny: int
    rho: tuple[tuple[int, int], ...]
    theta: tuple[tuple[int, int], tuple[int, int]]

    @property
    def bits(self) -> int:
        return 64 * self.nx * self.ny


ZC1280 = Variant(
    name="ZC-1280",
    nx=4,
    ny=5,
    rho=((0, 0), (1, 5), (3, 24), (0, 1), (2, 3)),
    theta=((1, 5), (1, 14)),
)
ZC1536 = Variant(
    name="ZC-1536",
    nx=8,
    ny=3,
    rho=((0, 0), (3, 3), (5, 0)),
    theta=((1, 20), (1, 56)),
)


def lane_rot(v: int, a: int) -> int:
    a %= 64
    return ((v << a) | (v >> (64 - a))) & MASK64 if a else v


def zero_state(v: Variant):
    return [[0 for _ in range(v.nx)] for _ in range(v.ny)]


def state_from_int(v: Variant, value: int):
    """Decode a bit string in the implementation order, y-major, x, then z."""
    a = zero_state(v)
    for y in range(v.ny):
        for x in range(v.nx):
            a[y][x] = (value >> (64 * (y * v.nx + x))) & MASK64
    return a


def state_to_int(v: Variant, a) -> int:
    value = 0
    for y in range(v.ny):
        for x in range(v.nx):
            value |= a[y][x] << (64 * (y * v.nx + x))
    return value


def xor_state(a, b):
    return [[u ^ v for u, v in zip(ar, br)] for ar, br in zip(a, b)]


def rho(v: Variant, a):
    out = [row[:] for row in a]
    for y, (dx, dz) in enumerate(v.rho):
        if not dx and not dz:
            continue
        row = [0] * v.nx
        for x in range(v.nx):
            row[(x + dx) % v.nx] = lane_rot(a[y][x], dz)
        out[y] = row
    return out


def chi(v: Variant, a):
    out = [row[:] for row in a]
    for y in range(v.ny):
        y1 = (y + 1) % v.ny
        y2 = (y + 2) % v.ny
        for x in range(v.nx):
            out[y][x] ^= ((~a[y1][x]) & a[y2][x]) & MASK64
    return out


def theta(v: Variant, a):
    p = [0] * v.nx
    for y in range(v.ny):
        for x in range(v.nx):
            p[x] ^= a[y][x]
    pr = [0] * v.nx
    for x in range(v.nx):
        pr[(x + 1) % v.nx] = p[x]
    e = [0] * v.nx
    for x in range(v.nx):
        e[x] = lane_rot(pr[x], v.theta[0][1]) ^ lane_rot(pr[x], v.theta[1][1])
    return [[a[y][x] ^ e[x] for x in range(v.nx)] for y in range(v.ny)]


def iota(v: Variant, a, rc: int):
    out = [row[:] for row in a]
    out[0][0] ^= rc
    return out


def round_function(v: Variant, a, rc: int):
    return rho(v, theta(v, rho(v, chi(v, iota(v, a, rc)))))


def permutation(v: Variant, a, nr: int = 12):
    if not 1 <= nr <= 12:
        raise ValueError("0 <= nr <= 12 is supported")
    out = [row[:] for row in a]
    for i in range(1 - nr, 1):
        out = round_function(v, out, ROUND_CONSTANTS[i])
    return out


def chi_inverse(v: Variant, a):
    out = zero_state(v)
    for x in range(v.nx):
        for z in range(64):
            out_column = sum(
                (((a[y][x] >> z) & 1) << y)
                for y in range(v.ny)
            )
            matches = []
            for candidate in range(1 << v.ny):
                mapped = 0
                for y in range(v.ny):
                    iy = (candidate >> y) & 1
                    iy1 = (candidate >> ((y + 1) % v.ny)) & 1
                    iy2 = (candidate >> ((y + 2) % v.ny)) & 1
                    mapped |= (iy ^ ((1 ^ iy1) & iy2)) << y
                if mapped == out_column:
                    matches.append(candidate)
            if len(matches) != 1:
                raise ValueError("chi is not bijective")
            input_column = matches[0]
            for y in range(v.ny):
                out[y][x] |= ((input_column >> y) & 1) << z
    return out


def rho_inverse(v: Variant, a):
    out = [row[:] for row in a]
    for y, (dx, dz) in enumerate(v.rho):
        if not dx and not dz:
            continue
        row = [0] * v.nx
        for x in range(v.nx):
            row[(x - dx) % v.nx] = lane_rot(a[y][x], -dz)
        out[y] = row
    return out


def _theta_linear_image(v: Variant, a):
    """Return E, which theta XORs into every plane."""
    p = [0] * v.nx
    for y in range(v.ny):
        for x in range(v.nx):
            p[x] ^= a[y][x]
    pr = [0] * v.nx
    for x in range(v.nx):
        pr[(x + 1) % v.nx] = p[x]
    return [
        lane_rot(pr[x], v.theta[0][1]) ^ lane_rot(pr[x], v.theta[1][1])
        for x in range(v.nx)
    ]


@lru_cache(maxsize=None)
def theta_inverse_rows(v: Variant):
    """Return rows of (I+Q)^-1 needed to recover the parity plane."""
    n = v.nx * 64
    images = []
    for x in range(v.nx):
        for z in range(64):
            unit = zero_state(v)
            unit[0][x] = 1 << z
            e = _theta_linear_image(v, unit)
            image_rows = [0] * v.nx
            for xx in range(v.nx):
                for zz in range(64):
                    if (e[xx] >> zz) & 1:
                        image_rows[xx] ^= (1 << zz)
            image_rows[x] ^= (1 << z)
            image = 0
            for xx in range(v.nx):
                image |= image_rows[xx] << (64 * xx)
            images.append(image)
    matrix_rows = [0] * n
    for input_bit, image in enumerate(images):
        for output_bit in range(n):
            if (image >> output_bit) & 1:
                matrix_rows[output_bit] |= 1 << input_bit
    inverse_rows = [1 << r for r in range(n)]
    for col in range(n):
        pivot = next(
            (r for r in range(col, n) if (matrix_rows[r] >> col) & 1),
            None,
        )
        if pivot is None:
            raise ValueError("theta map is singular")
        if pivot != col:
            matrix_rows[col], matrix_rows[pivot] = matrix_rows[pivot], matrix_rows[col]
            inverse_rows[col], inverse_rows[pivot] = inverse_rows[pivot], inverse_rows[col]
        for r in range(n):
            if r != col and ((matrix_rows[r] >> col) & 1):
                matrix_rows[r] ^= matrix_rows[col]
                inverse_rows[r] ^= inverse_rows[col]
    if any(matrix_rows[r] != (1 << r) for r in range(n)):
        raise ValueError("theta map is singular")
    # inverse_rows now stores the rows of M^-1. Solving M*x=e_i gives the
    # i-th column of M^-1, not its i-th row.
    return tuple(
        sum(
            (((inverse_rows[r] >> out_bit) & 1) << r)
            for r in range(n)
        )
        for out_bit in range(n)
    )


def theta_inverse(v: Variant, a):
    """Invert theta.

    Since v.ny is 5 or 3 (odd), if P_out = P_in xor v.ny*Q(P_in), then
    P_out = (I+Q)(P_in) over GF(2).
    """
    inv_rows = theta_inverse_rows(v)
    p_out = [0] * v.nx
    for y in range(v.ny):
        for x in range(v.nx):
            p_out[x] ^= a[y][x]
    p_in = [0] * v.nx
    for j, row in enumerate(inv_rows):
        if (p_out[j // 64] >> (j % 64)) & 1:
            for x in range(v.nx):
                p_in[x] ^= (row >> (64 * x)) & MASK64
    e = _theta_linear_image(v, [[p_in[x] if y == 0 else 0 for x in range(v.nx)] for y in range(v.ny)])
    return [[a[y][x] ^ e[x] for x in range(v.nx)] for y in range(v.ny)]


def round_inverse(v: Variant, a, rc: int):
    a = rho_inverse(v, a)
    a = theta_inverse(v, a)
    a = rho_inverse(v, a)
    a = chi_inverse(v, a)
    return iota(v, a, rc)


def permutation_inverse(v: Variant, a, nr: int = 12):
    out = [row[:] for row in a]
    for i in range(0, -nr, -1):
        out = round_inverse(v, out, ROUND_CONSTANTS[i])
    return out


def pad(message: bytes, rate: int) -> tuple[bytes, list[int]]:
    """Specification padding, MSB-first bit concatenation and parsing."""
    original_bits = len(message) * 8
    bits = [
        (byte >> (7 - i)) & 1
        for byte in message
        for i in range(8)
    ]
    bits.extend([0, 1])
    j = (-(original_bits + 4)) % rate
    bits.extend([1] + [0] * j + [1])
    assert len(bits) % rate == 0
    blocks = []
    for off in range(0, len(bits), rate):
        block = 0
        for bit in bits[off:off + rate]:
            block = (block << 1) | bit
        blocks.append(block)
    return bytes(bits), blocks


def bits_to_int_msb(bits: bytes) -> int:
    value = 0
    for byte in bits:
        value = (value << 8) | byte
    return value


def lane_block(block: int, rate: int):
    value = block << (1280 - rate if rate > 1024 else 1536 - rate)
    # This helper only exists to document leading-bit alignment; mode code
    # performs explicit bit placement instead.
    raise NotImplementedError


def block_to_state(v: Variant, block: int, rate: int):
    """Place rate bits in leading state positions using implementation order."""
    a = zero_state(v)
    for k in range(rate):
        # State implementation order is y-major, x, then z. Map leading MSB
        # message bits to increasing state-array positions.
        pos = k
        y = pos // (64 * v.nx)
        x = (pos // 64) % v.nx
        z = 63 - (pos % 64)
        bit = (block >> (rate - 1 - k)) & 1
        a[y][x] |= bit << z
    return a


def state_rate_to_int(v: Variant, a, rate: int) -> int:
    value = 0
    for k in range(rate):
        pos = k
        y = pos // (64 * v.nx)
        x = (pos // 64) % v.nx
        z = 63 - (pos % 64)
        value = (value << 1) | ((a[y][x] >> z) & 1)
    return value


def state_rate_bytes(v: Variant, a, rate: int) -> bytes:
    value = state_rate_to_int(v, a, rate)
    return value.to_bytes(rate // 8, "big")


def serialized_coordinate(v: Variant, serialization: str, index: int):
    """Coordinate corresponding to one serialized state bit.

    The specification gives coordinates but no serialization. The two cases
    are the canonical plane-minor and plane-major byte/lane orders requested by
    independent review.
    """
    if not 0 <= index < v.bits:
        raise ValueError("serialized bit index outside state")
    lane, z = divmod(index, 64)
    if serialization == "x-major":
        x, y = divmod(lane, v.ny)
    elif serialization == "y-major":
        y, x = divmod(lane, v.nx)
    else:
        raise ValueError(f"unknown serialization {serialization}")
    return x, y, z


def bits_to_state(v: Variant, serialization: str, bits: list[int]):
    a = zero_state(v)
    for index, bit in enumerate(bits):
        x, y, z = serialized_coordinate(v, serialization, index)
        a[y][x] |= bit << z
    return a


def state_to_bits(v: Variant, serialization: str, a, count: int):
    return [
        (a[y][x] >> z) & 1
        for x, y, z in (
            serialized_coordinate(v, serialization, index)
            for index in range(count)
        )
    ]


def message_bits(message: bytes):
    return [
        (byte >> (7 - i)) & 1
        for byte in message
        for i in range(8)
    ]


def padded_bits(message: bytes, rate: int):
    bits = message_bits(message)
    bits.extend([0, 1])
    j = (-(len(bits) + 2)) % rate
    bits.extend([1] + [0] * j + [1])
    assert len(bits) % rate == 0
    return bits


def hash_zc_dm_serialized(
    v: Variant,
    digest_bits: int,
    message: bytes,
    serialization: str,
    nr: int = 12,
):
    capacity = digest_bits + 64
    rate = v.bits - capacity
    bits = padded_bits(message, rate)
    state = bits_to_state(v, serialization, bits[:rate])
    for off in range(rate, len(bits), rate):
        pstate = permutation(v, state, nr)
        state = xor_state(xor_state(pstate, state), bits_to_state(v, serialization, bits[off:off + rate]))
    state = xor_state(permutation(v, state, nr), state)
    out = []
    while len(out) < digest_bits:
        out.extend(state_to_bits(v, serialization, state, rate))
        if len(out) < digest_bits:
            state = permutation(v, state, nr)
    out = out[:digest_bits]
    return bytes(
        sum(out[off + i] << (7 - i) for i in range(8))
        for off in range(0, digest_bits, 8)
    )


def interoperability_vector():
    msg_bits = "10110011100011110000111101010101" * 4
    message = int(msg_bits, 2).to_bytes(len(msg_bits) // 8, "big")
    return {
        "profile": "ZC-1280-DM-512",
        "message_bits": msg_bits,
        "message_sha256": hashlib.sha256(message).hexdigest(),
        "digest": {
            serialization: hash_zc_dm_serialized(
                ZC1280, 512, message, serialization
            ).hex()
            for serialization in ("x-major", "y-major")
        },
    }


def hash_zc_dm(v: Variant, digest_bits: int, message: bytes, nr: int = 12) -> bytes:
    capacity = digest_bits + 64
    rate = v.bits - capacity
    _, blocks = pad(message, rate)
    state = block_to_state(v, blocks[0], rate)
    for block in blocks[1:]:
        pstate = permutation(v, state, nr)
        state = xor_state(xor_state(pstate, state), block_to_state(v, block, rate))
    state = xor_state(permutation(v, state, nr), state)
    out = bytearray()
    while len(out) * 8 < digest_bits:
        out.extend(state_rate_bytes(v, state, rate))
        if len(out) * 8 < digest_bits:
            state = permutation(v, state, nr)
    return bytes(out[: (digest_bits + 7) // 8])


def self_test(seed: int = 20261121) -> dict:
    rng = random.Random(seed)
    report = {"seed": seed, "variants": {}}
    for v in (ZC1280, ZC1536):
        vr = {"roundtrip": {}, "profiles": {}}
        for nr in (1, 2, 3, 12):
            for _ in range(8):
                a = state_from_int(v, rng.getrandbits(v.bits))
                b = permutation(v, a, nr)
                c = permutation_inverse(v, b, nr)
                assert c == a, (v.name, nr)
            vr["roundtrip"][nr] = "pass"
        for n in (512, 768, 1024):
            c = n + 64
            r = v.bits - c
            for msg_len in (0, 1, max(0, r // 8 - 5), r // 8 - 4, r // 8, 100):
                msg = bytes(rng.randrange(256) for _ in range(msg_len))
                h = hash_zc_dm(v, n, msg)
                assert len(h) == n // 8
            vr["profiles"][str(n)] = {
                "m": v.bits,
                "c": c,
                "r": r,
                "zero_message_sha256": hashlib.sha256(hash_zc_dm(v, n, b"")).hexdigest(),
            }
        report["variants"][v.name] = vr
    return report


def main():
    command = sys.argv[1] if len(sys.argv) > 1 else "self-test"
    if command == "self-test":
        print(json.dumps(self_test(), indent=2, sort_keys=True))
    elif command == "roundtrip":
        v = ZC1280 if sys.argv[2] == "1280" else ZC1536
        nr = int(sys.argv[3])
        value = int(sys.argv[4], 0)
        a = state_from_int(v, value)
        b = permutation(v, a, nr)
        c = permutation_inverse(v, b, nr)
        print(json.dumps({
            "variant": v.name,
            "rounds": nr,
            "input": hex(value),
            "permutation": hex(state_to_int(v, b)),
            "inverse": hex(state_to_int(v, c)),
            "roundtrip": c == a,
        }, indent=2))
    elif command == "interoperability-vector":
        print(json.dumps(interoperability_vector(), indent=2, sort_keys=True))
    else:
        raise SystemExit(f"unknown command {command}")


if __name__ == "__main__":
    main()
