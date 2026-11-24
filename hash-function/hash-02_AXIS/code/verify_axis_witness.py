#!/usr/bin/env python3
"""Recompute the finite AXIS-512 divergence witness."""

import axis_semantics as a

SNAPSHOT = bytes.fromhex(
    "1446eb0aa6ad90cbb0b28b4b32cd8d3e"
    "b2c44e05eae0690bcd2d6cd6264a0056"
    "274a0cb81396e73cdbedc29a72f621f2"
    "ac822e954c6a3249e8852a04906999af"
)
ASCENDING = bytes.fromhex(
    "41940e5f1e18a758d792f3916d520944"
    "920f2d49de5398a055e3df867d15adc9"
    "4cbd53eba7732ac111e5934456752562"
    "46d3f91fa979d24fd69a5e8341f42187"
)


def to_bytes(bits):
    returned_bits = reversed(bits)
    out = bytearray()
    for i in range(0, 512, 8):
        byte = 0
        for b in [next(returned_bits) for _ in range(8)]:
            byte = (byte << 1) | b
        out.append(byte)
    return bytes(out)


def main():
    expected_beat0 = {
        "snapshot": [
            "487ed5110b4611a76fc2a2c515da54d53c6ef372fe94f82a",
            "c2c98d6eb17214edb03f0ca0647927f09394edc33f271b48",
            "c1f6ee49596ec5ef6a997bc6becb398f9ae384af6ea5dd6a",
            "bfa5cd69f756fd9a62406ab60293ad728fd4299f4fa870ae",
            "d6c69de80923355407f25af6ff5dde20bb9a4e6a665c8052",
            "a783459ad89bcfc79a10280adf4dd01faaf5883d08a691a8",
            "e7ff20ac5f33b5ca6a5fecc678dde74557b7ea74128ece6b",
            "434ce1a6ca7f6b71b28ae0460af3f0241b0eb720de4eda59",
        ],
        "ascending": [
            "487ed5110b4611a76fc2a2c515da54d53c6ef372fe94f82a",
            "c2c98d6eb17214edb03f0ca0647927f09394edc33f271b48",
            "c1f6ee49596ec5ef6a997bc6becb398f9ae384af6ea5dd6a",
            "bfa5cd69f756fd9a62406ab60293ad728fd4299f4fa870ae",
            "f6ce9de00923355407f25af6f75dce28bb9a4e6a665c8052",
            "878b4592d89bcfc79a10280ad74dc017aaf5883d08a691a8",
            "c7f720a45f33b5ca6a5fecc670ddf74d57b7ea74128ece6b",
            "6344e1aeca7f6b71b28ae04602f3e02c1b0eb720de4eda59",
        ],
    }
    observed = {}
    for semantic, label in (
        ("simultaneous", "snapshot"),
        ("ascending", "ascending"),
    ):
        bits, _, trace = a.axis("", 512, semantic)
        observed[label] = to_bytes(bits)
        assert [f"{word:048x}" for word in trace[0][1]] == expected_beat0[label]
    assert observed["snapshot"] == SNAPSHOT
    assert observed["ascending"] == ASCENDING
    assert observed["snapshot"] != observed["ascending"]
    print("verified")


if __name__ == "__main__":
    main()
