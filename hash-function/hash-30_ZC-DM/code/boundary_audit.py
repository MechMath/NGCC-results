#!/usr/bin/env python3
"""Audit the explicit ZC-DM padding boundary and all six squeeze profiles.

This is a local arithmetic check only. The research result is the proof in
INTERFACE_AUDIT.md, independently admitted as node 7742ba85e8a04340.
"""

from math import ceil


RATES = (192, 448, 704, 960)
PROFILES = (
    ("ZC-1280-DM-512", 1280, 512, 576, 704),
    ("ZC-1536-DM-512", 1536, 512, 576, 960),
    ("ZC-1280-DM-768", 1280, 768, 832, 448),
    ("ZC-1536-DM-768", 1536, 768, 832, 704),
    ("ZC-1280-DM-1024", 1280, 1024, 1088, 192),
    ("ZC-1536-DM-1024", 1536, 1024, 1088, 448),
)


def main() -> None:
    for rate in RATES:
        extra = [
            residue
            for residue in range(rate)
            if (residue + 4 + rate - 1) // rate == 2
        ]
        print(f"r={rate}: extra-block residues {extra}")

    for name, m, n, capacity, rate in PROFILES:
        assert capacity == n + 64
        assert rate == m - capacity
        extraction_blocks = ceil(n / rate)
        squeeze_permutations = extraction_blocks - 1
        stream_bits = extraction_blocks * rate
        print(
            f"{name}: r={rate}, n={n}, extraction_blocks={extraction_blocks}, "
            f"squeeze_permutations={squeeze_permutations}, "
            f"stream_bits={stream_bits}, truncated_bits={stream_bits - n}"
        )


if __name__ == "__main__":
    main()
