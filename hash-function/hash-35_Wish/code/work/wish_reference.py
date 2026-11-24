#!/usr/bin/env python3
"""Reference model for the original Wish v1.0 specification.

This module follows the pinned hash-35 specification.  It is an independent
implementation for specification auditing, not a claimed official reference
implementation.  It supports the two final-block separator readings explicitly
present in the document:

* prose: theta = 0^(c-1) || 1
* Algorithm 2: theta = 1^c
"""

from __future__ import annotations

import hashlib


SBOX = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
    0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0,
    0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC,
    0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A,
    0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0,
    0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B,
    0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85,
    0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,
    0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17,
    0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88,
    0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C,
    0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9,
    0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6,
    0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E,
    0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94,
    0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68,
    0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)


MIX_1024 = (
    0, 16, 32, 48, 1, 17, 33, 49, 64, 80, 96, 112, 65, 81, 97, 113,
    8, 24, 40, 56, 9, 25, 41, 57, 72, 88, 104, 120, 73, 89, 105, 121,
    4, 20, 36, 52, 5, 21, 37, 53, 68, 84, 100, 116, 69, 85, 101, 117,
    12, 28, 44, 60, 13, 29, 45, 61, 76, 92, 108, 124, 77, 93, 109, 125,
    2, 18, 34, 50, 3, 19, 35, 51, 66, 82, 98, 114, 67, 83, 99, 115,
    10, 26, 42, 58, 11, 27, 43, 59, 74, 90, 106, 122, 75, 91, 107, 123,
    6, 22, 38, 54, 7, 23, 39, 55, 70, 86, 102, 118, 71, 87, 103, 119,
    14, 30, 46, 62, 15, 31, 47, 63, 78, 94, 110, 126, 79, 95, 111, 127,
)


MIX_2048 = (
    0, 16, 32, 48, 64, 80, 96, 112, 128, 144, 160, 176, 192, 208, 224, 240,
    8, 24, 40, 56, 72, 88, 104, 120, 136, 152, 168, 184, 200, 216, 232, 248,
    4, 20, 36, 52, 68, 84, 100, 116, 132, 148, 164, 180, 196, 212, 228, 244,
    12, 28, 44, 60, 76, 92, 108, 124, 140, 156, 172, 188, 204, 220, 236, 252,
    2, 18, 34, 50, 66, 82, 98, 114, 130, 146, 162, 178, 194, 210, 226, 242,
    10, 26, 42, 58, 74, 90, 106, 122, 138, 154, 170, 186, 202, 218, 234, 250,
    6, 22, 38, 54, 70, 86, 102, 118, 134, 150, 166, 182, 198, 214, 230, 246,
    14, 30, 46, 62, 78, 94, 110, 126, 142, 158, 174, 190, 206, 222, 238, 254,
    1, 17, 33, 49, 65, 81, 97, 113, 129, 145, 161, 177, 193, 209, 225, 241,
    9, 25, 41, 57, 73, 89, 105, 121, 137, 153, 169, 185, 201, 217, 233, 249,
    5, 21, 37, 53, 69, 85, 101, 117, 133, 149, 165, 181, 197, 213, 229, 245,
    13, 29, 45, 61, 77, 93, 109, 125, 141, 157, 173, 189, 205, 221, 237, 253,
    3, 19, 35, 51, 67, 83, 99, 115, 131, 147, 163, 179, 195, 211, 227, 243,
    11, 27, 43, 59, 75, 91, 107, 123, 139, 155, 171, 187, 203, 219, 235, 251,
    7, 23, 39, 55, 71, 87, 103, 119, 135, 151, 167, 183, 199, 215, 231, 247,
    15, 31, 47, 63, 79, 95, 111, 127, 143, 159, 175, 191, 207, 223, 239, 255,
)


def gf_mul(a: int, b: int) -> int:
    out = 0
    for _ in range(8):
        if b & 1:
            out ^= a
        high = a & 0x80
        a = (a << 1) & 0xFF
        if high:
            a ^= 0x1B
        b >>= 1
    return out


def aes_round_no_key(lane: bytes) -> bytes:
    assert len(lane) == 16
    state = [SBOX[x] for x in lane]

    # ShiftRows in the specification's row-major 4x4 byte layout.
    shifted = [0] * 16
    for row in range(4):
        for col in range(4):
            shifted[row + 4 * col] = state[row + 4 * ((col + row) & 3)]

    # MixColumns in the same layout.
    out = [0] * 16
    for col in range(4):
        c0, c1, c2, c3 = shifted[4 * col:4 * col + 4]
        out[4 * col + 0] = gf_mul(c0, 2) ^ gf_mul(c1, 3) ^ c2 ^ c3
        out[4 * col + 1] = c0 ^ gf_mul(c1, 2) ^ gf_mul(c2, 3) ^ c3
        out[4 * col + 2] = c0 ^ c1 ^ gf_mul(c2, 2) ^ gf_mul(c3, 3)
        out[4 * col + 3] = gf_mul(c0, 3) ^ c1 ^ c2 ^ gf_mul(c3, 2)
    return bytes(out)


def lfsr_byte(x: int) -> int:
    return ((x << 1) & 0xFF) | (((x >> 7) ^ (x >> 5)) & 1)


def round_constants() -> list[bytes]:
    current = bytes.fromhex("243f6a8885a308d313198a2e03707344")
    out = [current]
    for _ in range(23):
        current = bytes(lfsr_byte(x) for x in current)
        out.append(current)
    return out


RCON = round_constants()


class Wish:
    def __init__(self, *, state_bits: int, steps: int):
        if state_bits not in (1024, 2048):
            raise ValueError("state_bits must be 1024 or 2048")
        self.state_bits = state_bits
        self.steps = steps
        self.lanes = state_bits // 128
        self.rate_bytes = state_bits // 16
        self.capacity_bytes = state_bits // 16
        self.state_bytes = state_bits // 8
        self.mix = MIX_1024 if state_bits == 1024 else MIX_2048
        if len(self.mix) != self.state_bytes or sorted(self.mix) != list(range(self.state_bytes)):
            raise AssertionError("the printed Mix table is not a byte permutation")
        if state_bits == 1024 and steps != 9:
            raise ValueError("Wish-512 has 9 steps")
        if state_bits == 2048 and steps != 12:
            raise ValueError("Wish-1024 has 12 steps")

    def permutation(self, state: bytes, block_index: int) -> bytes:
        assert len(state) == self.state_bytes
        tau = block_index.to_bytes(8, "big") + bytes(8)
        out = bytearray(state)
        tweak_lane = self.lanes // 2
        tweak_start = 16 * tweak_lane
        for step in range(self.steps):
            for i, x in enumerate(tau):
                out[tweak_start + i] ^= x
            for lane in range(self.lanes):
                start = 16 * lane
                out[start:start + 16] = aes_round_no_key(out[start:start + 16])
            for i, x in enumerate(RCON[2 * step]):
                out[i] ^= x
            for lane in range(self.lanes):
                start = 16 * lane
                out[start:start + 16] = aes_round_no_key(out[start:start + 16])
            for i, x in enumerate(RCON[2 * step + 1]):
                out[i] ^= x
            out[:] = bytes(out[src] for src in self.mix)
        return bytes(out)

    def pad(self, message: bytes, *, bit_length: int | None = None) -> bytes:
        if bit_length is None:
            bit_length = len(message) * 8
        if bit_length < 0 or bit_length > len(message) * 8:
            raise ValueError("bit_length is inconsistent with message")
        rate_bits = self.rate_bytes * 8
        zeros = (-bit_length - 1) % rate_bits
        if bit_length % 8:
            raise ValueError("the byte helper supports byte-aligned messages")
        value = int.from_bytes(message, "big") if message else 0
        padded_bits = bit_length + 1 + zeros
        value = (value << (1 + zeros)) | (1 << zeros)
        return value.to_bytes(padded_bits // 8, "big")

    def theta(self, reading: str) -> bytes:
        if reading == "prose":
            return bytes(self.capacity_bytes - 1) + b"\x01"
        if reading == "algorithm":
            return bytes([0xFF]) * self.capacity_bytes
        raise ValueError("reading must be prose or algorithm")

    def hash(self, message: bytes, *, reading: str, bit_length: int | None = None) -> bytes:
        padded = self.pad(message, bit_length=bit_length)
        blocks = len(padded) // self.rate_bytes
        state = bytes(self.state_bytes)
        theta = self.theta(reading)
        for i in range(blocks):
            x = bytearray(state)
            block = padded[i * self.rate_bytes:(i + 1) * self.rate_bytes]
            x[:self.rate_bytes] = bytes(a ^ b for a, b in zip(x[:self.rate_bytes], block))
            if i == blocks - 1:
                start = self.rate_bytes
                x[start:] = bytes(a ^ b for a, b in zip(x[start:], theta))
            feed_forward = bytes(x[self.rate_bytes:])
            permuted = self.permutation(bytes(x), i)
            state = bytearray(permuted)
            start = self.rate_bytes
            state[start:] = bytes(a ^ b for a, b in zip(state[start:], feed_forward))
            state = bytes(state)
        return state[self.rate_bytes:]


WISH_512 = Wish(state_bits=1024, steps=9)
WISH_1024 = Wish(state_bits=2048, steps=12)


def audit() -> None:
    assert len(SBOX) == 256 and len(set(SBOX)) == 256
    assert sorted(MIX_1024) == list(range(128))
    assert sorted(MIX_2048) == list(range(256))
    expected_rc_1 = "497fd5110b4610a72632155d06e1e788"
    expected_rc_23 = "e8e66e0557eb50215e5a51ecfeca3482"
    assert RCON[1].hex() == expected_rc_1, (RCON[1].hex(), expected_rc_1)
    assert RCON[23].hex() == expected_rc_23, (RCON[23].hex(), expected_rc_23)

    messages = {
        "empty": b"",
        "abc": b"abc",
        "64B": bytes(range(64)),
        "65B": bytes(range(65)),
        "128B": hashlib.sha256(b"Wish audit").digest() * 4,
    }
    for label, wish in (("Wish-512", WISH_512), ("Wish-1024", WISH_1024)):
        print(label)
        for name, msg in messages.items():
            prose = wish.hash(msg, reading="prose")
            algorithm = wish.hash(msg, reading="algorithm")
            assert len(prose) == wish.capacity_bytes
            assert len(algorithm) == wish.capacity_bytes
            print(
                f"  {name:6s} equal={prose == algorithm} "
                f"prose={prose.hex()} algorithm={algorithm.hex()}"
            )


if __name__ == "__main__":
    audit()
