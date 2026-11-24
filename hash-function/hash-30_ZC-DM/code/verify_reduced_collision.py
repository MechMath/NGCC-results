#!/usr/bin/env python3
"""Verify the one-round capacity-collision witness as a two-block hash collision."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import reduced_capacity_collision as z


POSITIONS = [(y, x, 63 - bit) for y in range(z.NY) for x in range(z.NX) for bit in range(64)]
RATE_POS = POSITIONS[:z.RATE]
CAP_POS = POSITIONS[z.RATE:]


def xor_state(a, b):
    return [[u ^ v for u, v in zip(ar, br)] for ar, br in zip(a, b)]


def copy_state(a):
    return [row[:] for row in a]


def state_bits(a, positions):
    return [((a[y][x] >> bit) & 1) for y, x, bit in positions]


def state_from_bits(positions, bits):
    a = z.zero_state()
    for (y, x, bit), value in zip(positions, bits):
        if value:
            a[y][x] |= 1 << bit
    return a


def state_hex(a):
    return f"0x{z.state_int(a):0{2 * (z.BITS // 4)}x}"


def main():
    data = json.loads(Path("reduced_collision_result.json").read_text())
    witness = data["witness"]
    x = [[int(v, 16) for v in row] for row in witness["x_lanes_hex"]]
    y = [[int(v, 16) for v in row] for row in witness["y_lanes_hex"]]
    rc = z.ROUND_CONSTANTS[data["scope"]["round_index"]]

    fx = z.round_function(x, rc)
    fy = z.round_function(y, rc)
    cap_fx = state_bits(xor_state(fx, x), CAP_POS)
    cap_fy = state_bits(xor_state(fy, y), CAP_POS)
    assert cap_fx == cap_fy

    # The first padded block is the first 960 raw message bits verbatim.
    mx0 = state_bits(x, RATE_POS)
    my0 = state_bits(y, RATE_POS)

    # Set B_x to a block whose only nonzero bits are its fixed suffix.  The
    # common target U has capacity cap(F(x)) and rate rate(F(x)) xor B_x.
    bx_bits = [0] * z.RATE
    padding = [0, 1, 1, 0, 0, 0, 0, 1]
    bx_bits[-8:] = padding
    bx = state_from_bits(RATE_POS, bx_bits)
    u = xor_state(xor_state(fx, x), bx)

    # Recover B_y from the same U.
    fy_bits = state_bits(xor_state(fy, y), RATE_POS)
    u_bits = state_bits(u, RATE_POS)
    by_bits = [a ^ b for a, b in zip(fy_bits, u_bits)]
    by = state_from_bits(RATE_POS, by_bits)
    assert by_bits[-8:] == padding

    s1x = xor_state(xor_state(fx, x), bx)
    s1y = xor_state(xor_state(fy, y), by)
    assert s1x == s1y
    assert state_bits(s1x, CAP_POS) == cap_fx

    final_x = xor_state(z.round_function(s1x, rc), s1x)
    final_y = xor_state(z.round_function(s1y, rc), s1y)
    assert final_x == final_y

    digest_bits = state_bits(final_x, RATE_POS)[:512]
    digest = bytes(
        sum(digest_bits[i + j] << (7 - j) for j in range(8))
        for i in range(0, 512, 8)
    )

    # Only the final second block has the 01100001 padding suffix.
    msg_x_bits = mx0 + bx_bits[:-8]
    msg_y_bits = my0 + by_bits[:-8]
    msg_x = bytes(
        sum(msg_x_bits[i + j] << (7 - j) for j in range(8))
        for i in range(0, len(msg_x_bits), 8)
    )
    msg_y = bytes(
        sum(msg_y_bits[i + j] << (7 - j) for j in range(8))
        for i in range(0, len(msg_y_bits), 8)
    )
    assert msg_x != msg_y

    result = {
        "scope": data["scope"],
        "verification": {
            "capacity_equal": True,
            "first_transition_states_equal": True,
            "final_states_equal": True,
            "digest_bits": 512,
            "digest_hex": digest.hex(),
        },
        "messages": {
            "message_x_bits": len(msg_x_bits),
            "message_y_bits": len(msg_y_bits),
            "message_x_sha256": hashlib.sha256(msg_x).hexdigest(),
            "message_y_sha256": hashlib.sha256(msg_y).hexdigest(),
            "message_x_hex": msg_x.hex(),
            "message_y_hex": msg_y.hex(),
        },
        "second_blocks": {
            "block_x_bits": "".join(map(str, bx_bits)),
            "block_y_bits": "".join(map(str, by_bits)),
            "block_y_hex": bytes(
                sum(by_bits[i + j] << (7 - j) for j in range(8))
                for i in range(0, z.RATE, 8)
            ).hex(),
        },
        "states": {
            "x": state_hex(x),
            "y": state_hex(y),
            "cap_f_x": cap_fx,
            "cap_f_y": cap_fy,
            "first_transition": state_hex(s1x),
            "final": state_hex(final_x),
        },
    }
    Path("reduced_collision_verified.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n"
    )
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
