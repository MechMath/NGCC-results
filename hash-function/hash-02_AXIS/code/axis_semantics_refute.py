#!/usr/bin/env python3
"""Exact transcription of the displayed AXIS-512 update/digest equations.

The two update modes are kept separate:
  ascending -- UpFull's ordered UpRes calls observe earlier calls;
  snapshot  -- all eight UpRes calls observe the pre-beat register array.

Bit zero is the least significant bit throughout, matching the specification's
right-to-left bit-string indexing.
"""

from __future__ import annotations

import argparse
import hashlib


MASK192 = (1 << 192) - 1

# Right-to-left indexing (PDF p. 5).
EXL = [0, 12, 32, 96, 107, 125, 11]
UPL = [66, 75, 90, 162, 178, 188]

INIT = [
    0x243F6A8885A308D3B7E151628AED2A6A9E3779B97F4A7C15,
    0x7160C6B758B90A76D81F8650363C93F849CA76E19F938DA4,
    0x70FF7724ACB762F7B54CBDE35B659CC7CD71C257B752EEB5,
    0x4FD6E6B4FBAB7ECD3120355B0549D6B947EA14CFA7D43857,
    0x6B634EF404919AAA03F92D7B7FAEEF105DCD2735332E4029,
]
INIT.extend(
    [
        int("53C1A2C96C4DE7E3CD0814056FA6E00BD57AC41E845348D4", 16),
        int("F3FF90522F99DAE5352FF6633C6EFBA6ABDBF53A09476735", 16),
        int("B1A270D3653FB5B8D94570230179F8120D875B906F276D2C", 16),
    ]
)


def bit(x: int, i: int) -> int:
    return (x >> (i % 192)) & 1


def parity(xs: list[int]) -> int:
    return sum(xs) & 1


def sb2(x: int, hi: int, lo: int) -> int:
    """Two-bit slice X[hi,lo], with hi as the more significant SBox input."""
    return (bit(x, hi) << 1) | bit(x, lo)


def sbox6(x5: int, x4: int, x3: int, x2: int, x1: int, x0: int) -> int:
    return (x5 & x4) ^ (x3 & x2) ^ (x1 & x0)


def sbox3(x5x4: int, x3x2: int, x1x0: int) -> int:
    return sbox6(
        (x5x4 >> 1) & 1,
        x5x4 & 1,
        (x3x2 >> 1) & 1,
        x3x2 & 1,
        (x1x0 >> 1) & 1,
        x1x0 & 1,
    )


def upres(state: list[int], j: int, m: int) -> list[int]:
    """Return the state after one in-place register update."""
    out = state.copy()
    x = state[j]
    xp5 = state[(j + 5) % 8]
    xp3 = state[(j + 3) % 8]
    xp1 = state[(j + 1) % 8]
    xm1 = state[(j - 1) % 8]

    tau = sbox3(
        sb2(xp5, EXL[3], EXL[2]),
        sb2(xp3, EXL[5], EXL[1]),
        sb2(xp1, EXL[4], EXL[0]),
    )
    b = (
        m
        ^ sbox6(
            bit(x, EXL[5]),
            bit(x, EXL[2]),
            bit(x, EXL[4]),
            bit(x, EXL[1]),
            bit(x, EXL[3]),
            bit(x, EXL[0]),
        )
        ^ tau
        ^ bit(xm1, EXL[6])
    )
    t0 = parity([bit(x, EXL[2]), bit(x, EXL[1]), bit(x, EXL[0])]) ^ b
    t1 = parity([bit(x, EXL[5]), bit(x, EXL[4]), bit(x, EXL[3])]) ^ b

    for i in UPL[0:3]:
        if t1:
            x ^= 1 << i
    for i in UPL[3:6]:
        if t0:
            x ^= 1 << i

    # S_j[191,190,...,0] <- S_j[0,191,...,1]:
    # old bit i becomes new bit i-1 mod 192.
    x = ((x >> 1) | ((x & 1) << 191)) & MASK192
    out[j] = x
    return out


def full_beat(state: list[int], controls: list[int], mode: str) -> list[int]:
    assert len(controls) == 8
    if mode == "ascending":
        current = state
        for j in range(8):
            current = upres(current, j, controls[j])
        return current
    if mode == "snapshot":
        old = state
        updated = old.copy()
        for j in range(8):
            candidate = upres(old, j, controls[j])
            updated[j] = candidate[j]
        return updated
    raise ValueError(mode)


def full_beat_with_trace(
    state: list[int], controls: list[int], mode: str
) -> tuple[list[int], list[list[int]]]:
    """Variant returning each post-j state for the first-beat audit."""
    trace: list[list[int]] = []
    if mode == "ascending":
        current = state
        for j in range(8):
            current = upres(current, j, controls[j])
            trace.append(current.copy())
        return current, trace

    old = state
    fixed = old.copy()
    for j in range(8):
        candidate = upres(old, j, controls[j])
        fixed[j] = candidate[j]
        trace.append(fixed.copy())
    return fixed, trace


def upfull(state: list[int], m_mu: int, m_nu: int, mode: str) -> list[int]:
    controls = [m_mu, m_nu] + [0] * 6
    return full_beat(state, controls, mode)


def gen_digest(state: list[int]) -> tuple[int, int]:
    p = EXL[0]
    h_mu = bit(state[6], p) ^ bit(state[4], p) ^ (bit(state[2], p) & bit(state[0], p))
    h_nu = bit(state[7], p) ^ bit(state[5], p) ^ (bit(state[3], p) & bit(state[1], p))
    return h_mu, h_nu


def init_stream_bit(i: int) -> int:
    """Bit i of the infinite right-aligned stream (...||initS||initS)."""
    return (INIT[(i // 192) % 8] >> (i % 192)) & 1


def empty_message_controls(bit_order: str) -> list[tuple[int, int]]:
    # Displayed Pad10^62(empty) = 1 0^62 1 0^64, 128 bits total.
    displayed = "1" + "0" * 62 + "1" + "0" * 64
    if bit_order == "literal":
        # The specification makes bit 0 (and the first message beat) the
        # rightmost/lowest bit, so process the displayed pad right-to-left.
        stream = displayed[::-1]
    elif bit_order == "handoff":
        # The requested handoff orientation processes the displayed string
        # left-to-right, giving beat zero (m_mu,m_nu)=(0,1).
        stream = displayed
    else:
        raise ValueError(bit_order)
    return [(int(stream[2 * t + 1]), int(stream[2 * t])) for t in range(64)]


def axis512_empty(bit_order: str, mode: str) -> dict[str, object]:
    state = INIT.copy()
    first_words = [None] * 8
    first_trace: list[list[int]] = []
    message_controls = empty_message_controls(bit_order)

    for t, (mmu_t, mnu_t) in enumerate(message_controls):
        controls = [mmu_t, mnu_t] + [0] * 6
        if t == 0:
            state, first_trace = full_beat_with_trace(state, controls, mode)
            first_words = state.copy()
        else:
            state = full_beat(state, controls, mode)

    # C is 8*(NFinBeat+NDigGen)=10240 bits, but (...||initS||initS)
    # only needs the low bit stream at each 8-bit beat.
    cpos = 0
    for _ in range(1024):
        cs = [init_stream_bit(cpos + i) for i in range(8)]
        state = full_beat(state, cs, mode)
        cpos += 8

    pair_words: list[int] = []
    for _ in range(256):
        pair_words.append((lambda h: (h[0] << 1) | h[1])(gen_digest(state)))
        cs = [init_stream_bit(cpos + i) for i in range(8)]
        state = full_beat(state, cs, mode)
        cpos += 8

    hv = 0
    for pair in reversed(pair_words):
        hv = (hv << 2) | pair
    digest = f"{hv:0128x}"
    return {
        "bit_order": bit_order,
        "mode": mode,
        "digest": digest,
        "first_message_controls": message_controls[0],
        "nonzero_message_beats": [
            (t, pair) for t, pair in enumerate(message_controls) if pair != (0, 0)
        ],
        "digest_sha256": hashlib.sha256(bytes.fromhex(digest)).hexdigest(),
        "first_generated_hm": pair_words[0] >> 1,
        "first_generated_hn": pair_words[0] & 1,
        "final_output_first_hm": pair_words[-1] >> 1,
        "final_output_first_hn": pair_words[-1] & 1,
        "first_words": [f"{x:048x}" for x in first_words],
        "s4_trace": [f"{tr[4]:048x}" for tr in first_trace[4:]],
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--bit-order", choices=("literal", "handoff"), default="literal")
    args = ap.parse_args()
    for mode in ("snapshot", "ascending"):
        result = axis512_empty(args.bit_order, mode)
        print("bit order:", result["bit_order"])
        print(result["mode"])
        print(result["digest"])
        print("first beat (m_mu,m_nu)=", result["first_message_controls"])
        print("nonzero message beats:", result["nonzero_message_beats"])
        print(
            "first generated (h_mu,h_nu):",
            (result["first_generated_hm"], result["first_generated_hn"]),
        )
        print(
            "first returned (h_mu,h_nu):",
            (result["final_output_first_hm"], result["final_output_first_hn"]),
        )
        print("S4 after first beat:", result["first_words"][4])


if __name__ == "__main__":
    main()
