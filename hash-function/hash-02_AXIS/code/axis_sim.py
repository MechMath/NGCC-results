#!/usr/bin/env python3
"""Small bit-exact AXIS transcription from hash-02-spec.pdf.

The transcription intentionally supports both the textual `for j = 0 to 7`
mutation order and the "concurrently" interpretation for exploratory checks.
Only the PDF specification is used.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random

N = 192
EXL = (11, 125, 107, 96, 32, 12, 0)
UPL = (66, 75, 90, 162, 178, 188)

CONSTANTS = (
    0x243F6A8885A308D3B7E151628AED2A6A9E3779B97F4A7C15,
    0x7160C6B758B90A76D81F8650363C93F849CA76E19F938DA4,
    0x70FF7724ACB762F7B54CBDE35B659CC7CD71C257B752EEB5,
    0x4FD6E6B4FBAB7ECD3120355B0549D6B947EA14CFA7D43857,
    0x6B634EF404919AAA03F92D7B7FAEEF105DCD2735332E4029,
    0x53C1A2C96C4DE7E3CD0814056FA6E00BD57AC41E845348D4,
    0xF3FF90522F99DAE5352FF6633C6EFBA6ABDBF53A09476735,
    0xB1A270D3653FB5B8D94570230179F8120D875B906F276D2C,
)

MASK = (1 << N) - 1


def sbox6(bits: int) -> int:
    # (x5*x4) xor (x3*x2) xor (x1*x0), x0 is the low bit.
    return ((bits >> 5) & (bits >> 4) & 1) ^ (
        (bits >> 3) & (bits >> 2) & 1
    ) ^ ((bits >> 1) & bits & 1)


def packed_bits(regs: list[int], positions: list[int]) -> int:
    """Pack the first listed bit as x0."""
    out = 0
    for i, pos in enumerate(positions):
        out |= ((regs[pos // N] >> (pos % N)) & 1) << i
    return out


def one_beat(regs: list[int], message_bits: int, constant_bits: int | None = None,
             concurrent: bool = True) -> list[int]:
    """Perform UpFull (constant_bits None) or ReUpFull."""
    source = regs[:]
    new = regs[:] if concurrent else regs[:]
    for j in range(8):
        cur = source if concurrent else new
        assert cur is not None
        tau = sbox6(packed_bits(
            cur,
            [(j + 1) % 8 * N + EXL[0], (j + 1) % 8 * N + EXL[4],
             (j + 3) % 8 * N + EXL[1], (j + 3) % 8 * N + EXL[5],
             (j + 5) % 8 * N + EXL[2], (j + 5) % 8 * N + EXL[3]],
        ))
        self_nl = sbox6(packed_bits(
            cur,
            [j * N + EXL[0], j * N + EXL[3], j * N + EXL[1],
             j * N + EXL[4], j * N + EXL[2], j * N + EXL[5]],
        ))
        preceding = (cur[(j - 1) % 8] >> EXL[6]) & 1
        if constant_bits is None:
            m = (message_bits >> (j & 1)) & 1
        else:
            m = (constant_bits >> j) & 1
        b = m ^ self_nl ^ tau ^ preceding
        t0 = (
            ((cur[j] >> EXL[2]) ^ (cur[j] >> EXL[1]) ^ (cur[j] >> EXL[0]))
            & 1
        ) ^ b
        t1 = (
            ((cur[j] >> EXL[5]) ^ (cur[j] >> EXL[4]) ^ (cur[j] >> EXL[3]))
            & 1
        ) ^ b

        value = cur[j]
        for pos in UPL[0:3]:
            value ^= t1 << pos
        for pos in UPL[3:6]:
            value ^= t0 << pos
        value &= MASK
        value = ((value >> 1) | ((value & 1) << 191)) & MASK
        if concurrent:
            new[j] = value
        else:
            new[j] = value
    return new


def digest_bits(regs: list[int]) -> int:
    a = [(r >> EXL[0]) & 1 for r in regs]
    h_mu = a[6] ^ a[4] ^ (a[2] & a[0])
    h_nu = a[7] ^ a[5] ^ (a[3] & a[1])
    return h_mu | (h_nu << 1)


def padded(message: bytes) -> tuple[int, int]:
    bitlen = len(message) * 8
    z = (-bitlen - 3) % 64
    bits = int.from_bytes(message, "little")
    # Padding is appended in stream order (LSB first in this representation).
    bits |= 1 << bitlen
    zpos = bitlen + 1 + z
    bits |= 1 << zpos
    bits |= bitlen << (zpos + 1)
    return bits, bitlen + 1 + z + 1 + 1 + 64


def axis(message: bytes, variant: int, concurrent: bool = True,
         state: list[int] | None = None, trace: bool = False) -> tuple[bytes, dict]:
    assert variant in (512, 768, 1024)
    stream, length = padded(message)
    regs = list(CONSTANTS) if state is None else state[:]
    assert length % 64 == 0
    beats: list[tuple[int, int]] = []
    pos = 0
    if variant == 512:
        nbeats = length // 2
        for _ in range(nbeats):
            lo = (stream >> pos) & 1
            hi = (stream >> (pos + 1)) & 1
            beats.append((lo, hi))
            pos += 2
    elif variant == 1024:
        nbeats = length
        for _ in range(nbeats):
            bit = (stream >> pos) & 1
            beats.append((bit, bit))
            pos += 1
    else:
        while length - pos >= 192:
            # odd: two new bits, even: duplicate the first
            if pos % 192 == 0:
                b0 = (stream >> pos) & 1
                b1 = (stream >> (pos + 1)) & 1
                b2 = (stream >> (pos + 2)) & 1
                beats.extend(((b0, b0), (b1, b2)))
            pos += 3
        rem = length - pos
        for _ in range(rem):
            bit = (stream >> pos) & 1
            beats.append((bit, bit))
            pos += 1
    assert pos == length

    for pair in beats:
        regs = one_beat(regs, pair[0] | (pair[1] << 1), concurrent=concurrent)
    init_stream = sum(c << (N * j) for j, c in enumerate(CONSTANTS))
    init_length = 8 * N
    for i in range(1024):
        cb = (init_stream >> ((8 * i) % init_length)) & 0xFF
        regs = one_beat(regs, 0, cb, concurrent=concurrent)

    out_value = 0
    out_pos = 0
    traces = []
    nout = {512: 256, 768: 512, 1024: 1024}[variant]
    for i in range(nout):
        h = digest_bits(regs)
        if variant == 512:
            out_value |= h << out_pos
            out_pos += 2
        elif variant == 768:
            out_value |= (h if i & 1 else (h & 1)) << out_pos
            out_pos += 2 if i & 1 else 1
        else:
            out_value |= (h & 1) << out_pos
            out_pos += 1
        if trace:
            traces.append({"beat": i, "h": h, "state_sha256": hashlib.sha256(
                b"".join(r.to_bytes(24, "little") for r in regs)
            ).hexdigest()})
        cb = (init_stream >> ((8 * (1024 + i)) % init_length)) & 0xFF
        regs = one_beat(regs, 0, cb, concurrent=concurrent)
    assert out_pos == variant
    return out_value.to_bytes(variant // 8, "little"), {
        "padded_bits": length, "message_beats": len(beats),
        "trace": traces, "final_state": regs,
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("variant", type=int, choices=(512, 768, 1024))
    ap.add_argument("hex_message")
    ap.add_argument("--sequential", action="store_true")
    ap.add_argument("--trace", action="store_true")
    args = ap.parse_args()
    out, info = axis(bytes.fromhex(args.hex_message), args.variant,
                     concurrent=not args.sequential, trace=args.trace)
    info.pop("final_state", None)
    print(json.dumps({"digest": out.hex(), "info": info}, indent=2))


if __name__ == "__main__":
    main()
