#!/usr/bin/env python3
"""Reproduce the two Wish-512 empty-message digests from the pinned PDF.

This is a reproducibility note, not execution evidence. The verified evidence
is proof-graph node fe55b73fbab9adae and its verifier reproduction.
"""

import re

from pypdf import PdfReader


def gf_mul(a, b):
    out = 0
    for _ in range(8):
        if b & 1:
            out ^= a
        a = ((a << 1) ^ 0x11B) if a & 0x80 else a << 1
        b >>= 1
    return out & 0xFF


def gf_pow(a, exponent):
    out = 1
    while exponent:
        if exponent & 1:
            out = gf_mul(out, a)
        a = gf_mul(a, a)
        exponent >>= 1
    return out


def aes_affine(x):
    return (
        x
        ^ (((x << 1) | (x >> 7)) & 0xFF)
        ^ (((x << 2) | (x >> 6)) & 0xFF)
        ^ (((x << 3) | (x >> 5)) & 0xFF)
        ^ (((x << 4) | (x >> 4)) & 0xFF)
        ^ 0x63
    )


SBOX = [aes_affine(gf_pow(x, 254)) if x else 0x63 for x in range(256)]


def aesr(lane):
    state = [[SBOX[lane[4 * c + r]] for c in range(4)] for r in range(4)]
    shifted = [[state[r][(c + r) % 4] for c in range(4)] for r in range(4)]
    out = [[0] * 4 for _ in range(4)]
    for c in range(4):
        x0, x1, x2, x3 = [shifted[r][c] for r in range(4)]
        out[0][c] = gf_mul(x0, 2) ^ gf_mul(x1, 3) ^ x2 ^ x3
        out[1][c] = x0 ^ gf_mul(x1, 2) ^ gf_mul(x2, 3) ^ x3
        out[2][c] = x0 ^ x1 ^ gf_mul(x2, 2) ^ gf_mul(x3, 3)
        out[3][c] = gf_mul(x0, 3) ^ x1 ^ x2 ^ gf_mul(x3, 2)
    return bytes(out[r][c] for c in range(4) for r in range(4))


def load_parameters(pdf):
    rows = []
    for line in pdf.pages[5].extract_text().splitlines():
        fields = line.split()
        if len(fields) == 16 and all(field.isdigit() for field in fields):
            rows.append([int(field) for field in fields])
    mix = sum(rows[:8], [])
    assert sorted(mix) == list(range(128))

    constants = {}
    for line in "\n".join(page.extract_text() for page in pdf.pages).splitlines():
        match = re.match(
            r"\s*(\d+)\s+([0-9a-f]{32})"
            r"(?:\s+(\d+)\s+([0-9a-f]{32}))?\s*$",
            line,
        )
        if match:
            constants[int(match.group(1))] = bytes.fromhex(match.group(2))
            if match.group(3):
                constants[int(match.group(3))] = bytes.fromhex(match.group(4))
    round_constants = [constants[i] for i in range(24)]
    return mix, round_constants


def wish512_empty(pdf, theta):
    mix, round_constants = load_parameters(pdf)
    state = bytearray(b"\x80" + bytes(63) + theta)
    for step in range(9):
        for lane in range(8):
            state[16 * lane:16 * lane + 16] = aesr(state[16 * lane:16 * lane + 16])
        state[:16] = bytes(
            a ^ b for a, b in zip(state[:16], round_constants[2 * step])
        )
        for lane in range(8):
            state[16 * lane:16 * lane + 16] = aesr(state[16 * lane:16 * lane + 16])
        state[:16] = bytes(
            a ^ b for a, b in zip(state[:16], round_constants[2 * step + 1])
        )
        state = bytearray(bytes(state[i] for i in mix))

    # The first-block tweak is zero and the final feed-forward value is theta.
    return bytes(a ^ b for a, b in zip(state[64:], theta)).hex()


if __name__ == "__main__":
    reader = PdfReader("hash-35-spec.pdf")
    for theta, label in (
        (bytes(63) + b"\x01", "section_3.4"),
        (bytes([0xFF]) * 64, "algorithm_2"),
    ):
        print(label, wish512_empty(reader, theta))
