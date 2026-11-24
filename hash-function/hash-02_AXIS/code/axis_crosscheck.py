#!/usr/bin/env python3
"""Slow, list-based cross-check of axis_sim.py.

This is intentionally written as a separate implementation.  Each register is
a 192-element binary list in ascending bit-index order.  It is used only to
catch transcription mistakes in the optimized integer implementation.
"""

from __future__ import annotations

import hashlib
import json
import random

from axis_sim import axis_hash


# Mathematical array indices, reversing the PDF's printed left-to-right lists.
EXL = [0, 12, 32, 96, 107, 125, 11]
UPL = [66, 75, 90, 162, 178, 188]
C = [
    0x243F6A8885A308D3B7E151628AED2A6A9E3779B97F4A7C15,
    0x7160C6B758B90A76D81F8650363C93F849CA76E19F938DA4,
    0x70FF7724ACB762F7B54CBDE35B659CC7CD71C257B752EEB5,
    0x4FD6E6B4FBAB7ECD3120355B0549D6B947EA14CFA7D43857,
    0x6B634EF404919AAA03F92D7B7FAEEF105DCD2735332E4029,
    0x53C1A2C96C4DE7E3CD0814056FA6E00BD57AC41E845348D4,
    0xF3FF90522F99DAE5352FF6633C6EFBA6ABDBF53A09476735,
    0xB1A270D3653FB5B8D94570230179F8120D875B906F276D2C,
]
SPEC = {512: (1024, 256), 768: (1024, 512), 1024: (1024, 1024)}


def pad(bits: list[int]) -> list[int]:
    original = bits.copy()
    length = len(original)
    s = (-length - 3) % 64
    bits.append(1)
    bits.extend([0] * (s + 1))
    bits.append(1)
    bits.extend((length >> i) & 1 for i in range(64))
    assert len(bits) % 64 == 0
    return bits


def sb(x: list[int]) -> int:
    return (x[0] & x[1]) ^ (x[2] & x[3]) ^ (x[4] & x[5])


def digest(instance: int, message_hex: str, return_trace: bool = False):
    message = bytes.fromhex(message_hex)
    bits: list[int] = []
    for byte in message:
        bits.extend((byte >> i) & 1 for i in range(8))
    padded = pad(bits)
    registers = [[(constant >> i) & 1 for i in range(192)] for constant in C]
    init = [bit for register in registers for bit in register]
    assert len(init) == 1536
    trace: list[dict[str, object]] = [
        {"phase": "init", "beat": -1, "state": [r.copy() for r in registers]}
    ]

    def up_res(j: int, m: int) -> None:
        r = registers[j]
        r5 = registers[(j + 5) % 8]
        r3 = registers[(j + 3) % 8]
        r1 = registers[(j + 1) % 8]
        rm1 = registers[(j - 1) % 8]
        tau = sb(
            [
                r5[EXL[3]],
                r5[EXL[2]],
                r3[EXL[5]],
                r3[EXL[1]],
                r1[EXL[4]],
                r1[EXL[0]],
            ]
        )
        own = sb([r[EXL[5]], r[EXL[2]], r[EXL[4]], r[EXL[1]], r[EXL[3]], r[EXL[0]]])
        b = m ^ own ^ tau ^ rm1[EXL[6]]
        t0 = r[EXL[2]] ^ r[EXL[1]] ^ r[EXL[0]] ^ b
        t1 = r[EXL[5]] ^ r[EXL[4]] ^ r[EXL[3]] ^ b
        for i in [UPL[2], UPL[1], UPL[0]]:
            r[i] ^= t1
        for i in [UPL[5], UPL[4], UPL[3]]:
            r[i] ^= t0
        # In ascending index order, S[i+1] <- S[i] prepends old S[191].
        registers[j] = r[-1:] + r[:-1]

    def up_full(mu: int, nu: int) -> None:
        for j in range(8):
            up_res(j, mu if j % 2 == 0 else nu)

    padded_len = len(padded)
    if instance == 512:
        message_beats = padded_len // 2
        schedule = [(padded[2 * t], padded[2 * t + 1]) for t in range(message_beats)]
    elif instance == 1024:
        message_beats = padded_len
        schedule = [(padded[t], padded[t]) for t in range(message_beats)]
    else:
        rem = padded_len % 192
        if rem == 0:
            message_beats = 2 * padded_len // 3
        elif rem == 64:
            message_beats = (2 * padded_len + 64) // 3
        else:
            message_beats = (2 * padded_len + 32) // 3
        tail = 64 if rem == 64 else 32 if rem == 128 else 0
        schedule = []
        for t in range(message_beats):
            if t >= message_beats - tail:
                i = padded_len - tail + t - (message_beats - tail)
                schedule.append((padded[i], padded[i]))
            elif t % 2 == 0:
                i = 3 * t // 2
                schedule.append((padded[i], padded[i]))
            else:
                i = (3 * t - 1) // 2
                schedule.append((padded[i], padded[i + 1]))

    for mu, nu in schedule:
        up_full(mu, nu)
        if return_trace:
            trace.append(
                {
                    "phase": "message",
                    "beat": len(trace) - 1,
                    "pair": [mu, nu],
                    "state": [r.copy() for r in registers],
                }
            )

    nfin, ndig = SPEC[instance]
    if return_trace:
        trace.append(
            {
                "phase": "message_end",
                "state": [r.copy() for r in registers],
            }
        )
    for beat in range(nfin):
        for j in range(8):
            up_res(j, init[(8 * beat + j) % 1536])
        if return_trace:
            trace.append(
                {
                    "phase": "finalization",
                    "beat": beat,
                    "state": [r.copy() for r in registers],
                }
            )

    out: list[int] = []
    for beat in range(ndig):
        mu = registers[6][0] ^ registers[4][0] ^ (registers[2][0] & registers[0][0])
        nu = registers[7][0] ^ registers[5][0] ^ (registers[3][0] & registers[1][0])
        if instance == 512:
            out.extend((nu, mu))
        elif instance == 768:
            out.extend((mu,) if beat % 2 == 0 else (nu, mu))
        else:
            out.append(mu)
        for j in range(8):
            up_res(j, init[(8 * (nfin + beat) + j) % 1536])

    assert len(out) == instance
    result = sum(bit << i for i, bit in enumerate(out)).to_bytes(instance // 8, "little").hex()
    if return_trace:
        return result, trace
    return result


def main() -> None:
    rng = random.Random(0xA715)
    cases = [b"", b"abc", b"\x00", b"\xff" * 17]
    cases.extend(rng.randbytes(rng.randrange(0, 257)) for _ in range(12))
    checked = []
    for instance in (512, 768, 1024):
        for message in cases:
            fast = axis_hash(instance, message).digest_hex_low_bit_first
            slow = digest(instance, message.hex())
            if fast != slow:
                raise AssertionError(
                    {"instance": instance, "message_hex": message.hex(), "fast": fast, "slow": slow}
                )
            checked.append(
                {
                    "instance": instance,
                    "message_len_bits": len(message) * 8,
                    "message_sha256": hashlib.sha256(message).hexdigest(),
                    "digest_hex": fast,
                }
            )
    print(
        json.dumps(
            {
                "status": "ok",
                "crosscheck_cases": len(checked),
                "implementation_independence": (
                    "integer registers vs separate 192-element bit-list registers; "
                    "schedules recomputed from PDF formulas"
                ),
                "conformance_status": "unresolved: allowlisted PDF has no digest KAT",
                "cases": checked,
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
