#!/usr/bin/env python3
"""Bit-exact ZC-EDMC absorption comparison for the allowlisted specification.

This script follows the prose padding definition on PDF page 13 and the
state/round definitions on PDF pages 5-11.  It compares the page-13 formula
F_hh(X) = h(h(X) xor (0^r || X_c))
with the page-15/Equation-1.1 formula
F_hg(X) = h(g(X) xor (0^r || X_c)).

The serialization used here is explicit: bit (x,y,z) occupies
64*(X_DIM*x + y) + z in a little-endian integer, while API bitstrings use
bit index zero as their leftmost bit when converted for display.
"""

from __future__ import annotations

import hashlib
import json


ROUND_CONSTANTS = {
    -11: 0x58,
    -10: 0x38,
    -9: 0x3C0,
    -8: 0xD0,
    -7: 0x60,
    -6: 0x120,
    -5: 0x14,
    -4: 0x2C,
    -3: 0xF0,
    -2: 0x1A0,
    -1: 0x380,
    0: 0x12,
}

PARAMS = {
    1280: {"planes": 5, "xdim": 4, "rho": [(1, 5), (3, 24), (0, 1), (2, 3)],
           "theta": [(1, 5), (1, 14)]},
    1536: {"planes": 3, "xdim": 8, "rho": [(3, 3), (5, 0)],
           "theta": [(1, 20), (1, 56)]},
}


def rot_left_lane(value: int, offset: int) -> int:
    offset %= 64
    return ((value << offset) | (value >> (64 - offset))) & ((1 << 64) - 1)


def rol(value: int, width: int, offset: int) -> int:
    offset %= width
    mask = (1 << width) - 1
    value &= mask
    return ((value << offset) | (value >> (width - offset))) & mask


def bit(
    state: list[list[int]], index: int, planes: int, xdim: int
) -> int:
    x, rem = divmod(index, planes * 64)
    y, z = divmod(rem, 64)
    assert x < xdim
    return (state[x][y] >> z) & 1


def set_bit(
    state: list[list[int]], index: int, value: int, planes: int, xdim: int
) -> None:
    x, rem = divmod(index, planes * 64)
    y, z = divmod(rem, 64)
    assert x < xdim
    if value:
        state[x][y] |= 1 << z
    else:
        state[x][y] &= ~(1 << z)


def coordinate(index: int, m: int, layout: str, reverse_z: bool) -> tuple[int, int, int]:
    p = PARAMS[m]
    planes, xdim = p["planes"], p["xdim"]
    if layout == "x_major":
        x, rem = divmod(index, planes * 64)
        y, z = divmod(rem, 64)
    elif layout == "y_major":
        y, rem = divmod(index, xdim * 64)
        x, z = divmod(rem, 64)
    elif layout == "x_minor":
        z, rem = divmod(index, xdim * planes)
        x, y = divmod(rem, planes)
    elif layout == "y_minor":
        z, rem = divmod(index, xdim * planes)
        y, x = divmod(rem, xdim)
    else:
        raise ValueError(f"unknown layout {layout}")
    return x, y, (63 - z if reverse_z else z)


def layout_state_from_rate_bits(
    block: str, m: int, layout: str, reverse_z: bool
) -> list[list[int]]:
    state = zero_state(m)
    for index, value in enumerate(block):
        if int(value):
            x, y, z = coordinate(index, m, layout, reverse_z)
            state[x][y] |= 1 << z
    return state


def layout_api_string(
    state: list[list[int]], m: int, layout: str, reverse_z: bool
) -> str:
    return "".join(
        str((state[x][y] >> z) & 1)
        for index in range(m)
        for x, y, z in [coordinate(index, m, layout, reverse_z)]
    )


def round_once(state: list[list[int]], m: int, rc: int) -> list[list[int]]:
    p = PARAMS[m]
    planes, xdim = p["planes"], p["xdim"]
    state = [lanes[:] for lanes in state]

    # iota
    state[0][0] ^= rc

    # chi
    old = [lanes[:] for lanes in state]
    for x in range(xdim):
        for y in range(planes):
            state[x][y] = old[x][y] ^ (
                (~old[x][(y + 1) % planes]) & old[x][(y + 2) % planes]
            )
            state[x][y] &= (1 << 64) - 1

    def rho(layers: list[list[int]]) -> list[list[int]]:
        out = [lanes[:] for lanes in layers]
        for y, (dx, dz) in enumerate(p["rho"], start=1):
            for x in range(xdim):
                out[x][y] = rot_left_lane(layers[(x - dx) % xdim][y], dz)
        return out

    state = rho(state)

    # theta
    parity = [0] * xdim
    for x in range(xdim):
        for y in range(planes):
            parity[x] ^= state[x][y]
    effect = [0] * xdim
    for x in range(xdim):
        for dx, dz in p["theta"]:
            effect[x] ^= rol(parity[(x - dx) % xdim], 64, dz)
    for x in range(xdim):
        for y in range(planes):
            state[x][y] ^= effect[x]

    return rho(state)


def permute(state: list[list[int]], m: int, constants: list[int]) -> list[list[int]]:
    for rc in constants:
        state = round_once(state, m, rc)
    return state


def half_pair(m: int) -> tuple[list[int], list[int]]:
    return (
        [ROUND_CONSTANTS[i] for i in range(-11, -5)],
        [ROUND_CONSTANTS[i] for i in range(-5, 1)],
    )


def full_constants() -> list[int]:
    return [ROUND_CONSTANTS[i] for i in range(-11, 1)]


def xor_state(a: list[list[int]], b: list[list[int]]) -> list[list[int]]:
    return [[x ^ y for x, y in zip(ra, rb)] for ra, rb in zip(a, b)]


def zero_state(m: int) -> list[list[int]]:
    p = PARAMS[m]
    return [[0] * p["planes"] for _ in range(p["xdim"])]


def state_from_rate_bits(block: str, m: int) -> list[list[int]]:
    p = PARAMS[m]
    assert len(block) <= m
    state = zero_state(m)
    for i, value in enumerate(block):
        set_bit(state, i, int(value), p["planes"], p["xdim"])
    return state


def state_digest(state: list[list[int]], m: int) -> str:
    p = PARAMS[m]
    raw = "".join(
        str(bit(state, i, p["planes"], p["xdim"])) for i in range(m)
    )
    return hashlib.sha256(raw.encode("ascii")).hexdigest()


def squeeze_digest(
    state: list[list[int]], m: int, n: int, capacity: int
) -> str:
    p = PARAMS[m]
    r = m - capacity
    stream = "".join(
        str(bit(state, i, p["planes"], p["xdim"])) for i in range(r)
    )
    while len(stream) < n:
        state = permute(state, m, full_constants())
        stream += "".join(
            str(bit(state, i, p["planes"], p["xdim"])) for i in range(r)
        )
    return stream[:n]


def squeeze_digest_layout(
    state: list[list[int]], m: int, n: int, capacity: int,
    layout: str, reverse_z: bool
) -> str:
    r = m - capacity
    stream = layout_api_string(state, m, layout, reverse_z)[:r]
    while len(stream) < n:
        state = permute(state, m, full_constants())
        stream += layout_api_string(state, m, layout, reverse_z)[:r]
    return stream[:n]


def absorption_with_capacity(
    state: list[list[int]], m: int, capacity: int, mode: str
) -> list[list[int]]:
    g_consts, h_consts = half_pair(m)
    first = permute(state, m, h_consts if mode == "hh" else g_consts)
    p = PARAMS[m]
    for i in range(m - capacity, m):
        set_bit(
            first,
            i,
            bit(first, i, p["planes"], p["xdim"])
            ^ bit(state, i, p["planes"], p["xdim"]),
            p["planes"],
            p["xdim"],
        )
    second = permute(first, m, h_consts)
    return second


def padded_empty_message(r: int) -> str:
    # Prose page 13: M || 01 || 1 0^j 1 and alpha=ceil((|M|+4)/r).
    # For M empty, choose j=r-4.  This gives exactly one r-bit block.
    assert r >= 4
    padded = "01" + "1" + ("0" * (r - 4)) + "1"
    assert len(padded) == r
    return padded


def first_difference(a: list[list[int]], b: list[list[int]], m: int) -> dict:
    p = PARAMS[m]
    for index in range(m):
        va, vb = (
            bit(a, index, p["planes"], p["xdim"]),
            bit(b, index, p["planes"], p["xdim"]),
        )
        if va != vb:
            x, rem = divmod(index, p["planes"] * 64)
            y, z = divmod(rem, 64)
            return {
                "index": index,
                "coordinate": [x, y, z],
                "hh_bit": va,
                "hg_bit": vb,
            }
    return {}


def differing_positions(
    a: list[list[int]], b: list[list[int]], m: int
) -> list[int]:
    p = PARAMS[m]
    return [
        index
        for index in range(m)
        if bit(a, index, p["planes"], p["xdim"])
        != bit(b, index, p["planes"], p["xdim"])
    ]


def main() -> None:
    results = {}
    for m, n in ((1280, 512), (1280, 768), (1280, 1024),
                 (1536, 512), (1536, 768), (1536, 1024)):
        c = n + 64
        r = m - c
        block = padded_empty_message(r)
        x0 = state_from_rate_bits(block, m)
        f_hh = absorption_with_capacity(x0, m, c, "hh")
        f_hg = absorption_with_capacity(x0, m, c, "hg")
        p = PARAMS[m]
        digest_hh = squeeze_digest(f_hh, m, n, c)
        digest_hg = squeeze_digest(f_hg, m, n, c)
        assert digest_hh != digest_hg
        layout_checks = {}
        for layout in ("x_major", "y_major", "x_minor", "y_minor"):
            for reverse_z in (False, True):
                state = layout_state_from_rate_bits(
                    block, m, layout, reverse_z
                )
                out_hh = absorption_with_capacity(state, m, c, "hh")
                out_hg = absorption_with_capacity(state, m, c, "hg")
                key = f"{layout}:{'z_high' if reverse_z else 'z_low'}"
                layout_checks[key] = (
                    squeeze_digest_layout(
                        out_hh, m, n, c, layout, reverse_z
                    )
                    != squeeze_digest_layout(
                        out_hg, m, n, c, layout, reverse_z
                    )
                )
        assert all(layout_checks.values())
        results[f"{m}-{n}"] = {
            "m": m,
            "n": n,
            "c": c,
            "r": r,
            "message_bits": "empty",
            "message_bytes": 0,
            "padding_j": r - 4,
            "padded_block": block,
            "padded_length": len(block),
            "block_count": 1,
            "F_hh_full_state_sha256": state_digest(f_hh, m),
            "F_hg_full_state_sha256": state_digest(f_hg, m),
            "F_full_state_first_difference": first_difference(f_hh, f_hg, m),
            "F_full_state_difference_weight": len(
                differing_positions(f_hh, f_hg, m)
            ),
            "digest_hh_hex": f"{int(digest_hh, 2):0{n // 4}x}",
            "digest_hg_hex": f"{int(digest_hg, 2):0{n // 4}x}",
            "digest_equal": digest_hh == digest_hg,
            "all_eight_layouts_differ": all(layout_checks.values()),
            "layout_digest_equal": layout_checks,
        }
    print(json.dumps(results, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
