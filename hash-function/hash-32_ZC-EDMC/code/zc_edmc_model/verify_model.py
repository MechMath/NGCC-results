#!/usr/bin/env python3
"""Independent, unoptimized bit-level verifier for the recorded vectors."""

from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent
RESULTS = ROOT / "results.json"
CONSTANTS = [
    0x0000000000000058,
    0x0000000000000038,
    0x00000000000003C0,
    0x00000000000000D0,
    0x0000000000000060,
    0x0000000000000120,
    0x0000000000000014,
    0x000000000000002C,
    0x00000000000000F0,
    0x00000000000001A0,
    0x0000000000000380,
    0x0000000000000012,
]


def zero_state(width: int, planes: int) -> list:
    return [[[0 for _ in range(64)] for _ in range(width)] for _ in range(planes)]


def rho(state: list, shifts: list[tuple[int, int]]) -> list:
    out = zero_state(len(state[0]), len(state))
    for y, row in enumerate(state):
        dx, dz = shifts[y]
        for x in range(len(row)):
            for z in range(64):
                out[y][(x + dx) % len(row)][(z + dz) % 64] = row[x][z]
    return out


def chi(state: list) -> list:
    out = zero_state(len(state[0]), len(state))
    planes = len(state)
    for y in range(planes):
        for x in range(len(state[0])):
            for z in range(64):
                out[y][x][z] = (
                    state[y][x][z]
                    ^ ((1 - state[(y + 1) % planes][x][z]) & state[(y + 2) % planes][x][z])
                )
    return out


def theta(state: list, shifts: tuple[int, int]) -> list:
    planes = len(state)
    width = len(state[0])
    parity = zero_state(width, 1)[0]
    for y in range(planes):
        for x in range(width):
            for z in range(64):
                parity[x][z] ^= state[y][x][z]
    effect = zero_state(width, 1)[0]
    for x in range(width):
        for z in range(64):
            effect[x][z] = (
                parity[(x - 1) % width][(z - shifts[0]) % 64]
                ^ parity[(x - 1) % width][(z - shifts[1]) % 64]
            )
    return [
        [[state[y][x][z] ^ effect[x][z] for z in range(64)]
         for x in range(width)]
        for y in range(planes)
    ]


def permute(state: list, shifts: list[tuple[int, int]], theta_shifts: tuple[int, int]) -> list:
    return rounds(state, shifts, theta_shifts, 0, 12)


def rounds(
    state: list,
    shifts: list[tuple[int, int]],
    theta_shifts: tuple[int, int],
    start: int,
    stop: int,
) -> list:
    for round_index in range(start, stop):
        constant = CONSTANTS[round_index]
        for z in range(64):
            state[0][0][z] ^= (constant >> z) & 1
        state = chi(state)
        state = rho(state, shifts)
        state = theta(state, theta_shifts)
        state = rho(state, shifts)
    return state


def state_bits(state: list) -> list[int]:
    return [state[y][x][z] for x in range(len(state[0]))
            for y in range(len(state)) for z in range(64)]


def bits_to_bytes(bits: list[int]) -> bytes:
    if len(bits) % 8:
        raise ValueError("unaligned digest")
    return bytes(sum(bits[i + j] << (7 - j) for j in range(8))
                 for i in range(0, len(bits), 8))


def xor_capacity(state: list, original: list, rate: int) -> list:
    out = [[lane[:] for lane in row] for row in state]
    for index, bit in enumerate(state_bits(original)[rate:]):
        index += rate
        x = index // (64 * len(state))
        remainder = index % (64 * len(state))
        y = remainder // 64
        z = remainder % 64
        out[y][x][z] ^= bit
    return out


def feed_forward(
    state: list,
    original: list,
    rate: int,
    shifts: list[tuple[int, int]],
    theta_shifts: tuple[int, int],
    reading: str,
) -> list:
    start = 6 if reading == "hh" else 0
    first = [[lane[:] for lane in row] for row in state]
    if start == 0:
        first = rounds(first, shifts, theta_shifts, 0, 6)
    else:
        first = rounds(first, shifts, theta_shifts, 6, 12)
    fed = xor_capacity(first, original, rate)
    return rounds(fed, shifts, theta_shifts, 6, 12)


def digest(
    message_bits: list[int],
    rate: int,
    n: int,
    shifts: list[tuple[int, int]],
    theta_shifts: tuple[int, int],
    reading: str,
) -> bytes:
    j = (-(len(message_bits) + 4)) % rate
    padded = message_bits + [0, 1, 1] + [0] * j + [1]
    blocks = [padded[i:i + rate] for i in range(0, len(padded), rate)]
    state = zero_state(4, len(shifts))
    for bit_index, bit in enumerate(blocks[0]):
        x = bit_index // (64 * len(shifts))
        y = (bit_index % (64 * len(shifts))) // 64
        z = bit_index % 64
        state[y][x][z] = bit
    for block in blocks[1:]:
        state = feed_forward(state, state, rate, shifts, theta_shifts, reading)
        for bit_index, bit in enumerate(block):
            x = bit_index // (64 * len(shifts))
            y = (bit_index % (64 * len(shifts))) // 64
            z = bit_index % 64
            state[y][x][z] ^= bit
    state = feed_forward(state, state, rate, shifts, theta_shifts, reading)
    output = state_bits(state)[:rate]
    while len(output) < n:
        state = permute(state, shifts, theta_shifts)
        output.extend(state_bits(state)[:rate])
    return bits_to_bytes(output[:n])


def main() -> None:
    recorded = json.loads(RESULTS.read_text(encoding="utf-8"))
    checks = []
    for vector in recorded["vectors_recommended_profile"]:
        logical = vector["message_bits_logical"]
        aligned = bytes.fromhex(vector["message_hex_left_aligned"])
        bits = [(byte >> (7 - i)) & 1 for byte in aligned for i in range(8)][:logical]
        for reading in ("hh", "hg"):
            actual = digest(
                bits,
                704,
                512,
                [(0, 0), (1, 5), (3, 24), (0, 1), (2, 3)],
                (5, 14),
                reading,
            ).hex()
            expected = vector[f"digest_{reading}_hex"]
            checks.append({"label": vector["label"], "reading": reading, "match": actual == expected})
            if actual != expected:
                raise SystemExit(f"mismatch for {vector['label']} {reading}: {actual} != {expected}")
    result = {
        "all_match": all(item["match"] for item in checks),
        "checks": checks,
        "interpretation": (
            "Independent bit-array reproduction of the recorded vectors. "
            "This is an implementation cross-check, not crypto_run evidence."
        ),
    }
    rendered = json.dumps(result, indent=2) + "\n"
    (ROOT / "verification.json").write_text(rendered, encoding="utf-8")
    print(rendered, end="")


if __name__ == "__main__":
    main()
