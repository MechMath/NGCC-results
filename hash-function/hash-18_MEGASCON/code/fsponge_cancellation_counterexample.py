#!/usr/bin/env python3
"""Counterexample to the claimed two-block F-sponge XOR cancellation.

The checks use two independently written formal implementations of the
allowlisted MEGASCON specification.  For rate r, the differing message has
one set bit at external positions r-1 and 2r-1.
"""

from __future__ import annotations

import hashlib
import importlib.util
import sys
from pathlib import Path


RUN_ROOT = Path(__file__).resolve().parents[3]
WORKER_SLOT = RUN_ROOT / "run" / "slots" / "5088b97872a14ce6"
EXPECTED_IMPLEMENTATION_HASHES = {
    "megascon.py": "4dcbbf6a9d1c505d38d75ff70f6ab5bf29694508239301b5c847ccea895f163c",
    "bit_reference.py": "3dcfd93e207ff9679729f0f24e2709abfa5b1fd3e2b5b7aff484047a2645fb13",
}
EXPECTED = {
    ("Megascon-768", "megascon"): (
        "ce3896833e3df632369bf98f3dc5d6c96208866364e1485b764b0f2603334237"
        "a25e340c19aa012ab93ab8352341a670dadb14899652c2a0786d3f211385dfea"
        "cc43b694398e12fa641d19f22f20c472928050a0592ee55866a8bd3e65780ee9",
        "1ab4161ba85fac2b72f8129e37c60a85d8c1b4ca7e0c339f7da0a56daeaf0f8"
        "cda58c7ddad7bfaa9a20ce6d29b84dc6a71cd149b7ba9028f2933d2f43e8c07"
        "a0f3048caf59bd2bd857f576fa80a0e7344743bf5d45dde74a34bb14c8c2cd"
        "3574",
    ),
    ("Megascon-1024", "megascon"): (
        "e445e8c713ec8866a2c79ab3a17d64800d9f47d2f68e29712c2cf6aac00fb64a"
        "9b17fa8ac5317d062aaf85e064b26b10b7fe594ff7b99f3c04f1f2901881c0"
        "aeb95299315a6dceda3b319b8e8ae2cecfc4670fe9f7e7b6a1ff5aec5af9f0"
        "b9ea7c6219cc735dedfa847bcc036adc1be5d6f1b5b1030b8e9eb483cbe108"
        "48d58f",
        "8975de9c612f44d30797d2825a40bafdf0e154ed338fa0a9a0f71a969eceedb"
        "7d7edd06dd64bb179cf1545fde8240476cac130083a75d6604db0616b576b"
        "20734631e84c95e3a427d1fd39a4bb0d3a3fdfadefef3cd444262966f12a2a"
        "91661d2bdc94eaee60672a861c03b59f0743fd9f1c878042a47a06e4773e81"
        "f80b319a",
    ),
}


def load_module(name: str):
    path = WORKER_SLOT / f"{name}.py"
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    assert actual == EXPECTED_IMPLEMENTATION_HASHES[path.name], (path, actual)
    spec = importlib.util.spec_from_file_location(f"hash18_{name}", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def messages(rate: int) -> tuple[bytes, bytes]:
    zero = bytes(2 * rate // 8)
    differing = bytearray(zero)
    for bit_position in (rate - 1, 2 * rate - 1):
        differing[bit_position // 8] ^= 1 << (7 - bit_position % 8)
    return zero, bytes(differing)


def main() -> None:
    for implementation in ("megascon", "bit_reference"):
        module = load_module(implementation)
        for name, rate, digest_bits, rounds in (
            ("Megascon-768", 1216, 768, 24),
            ("Megascon-1024", 960, 1024, 24),
        ):
            message_a, message_b = messages(rate)
            digest_a = module.f_sponge(
                message_a, rate, rounds, digest_bits
            ).hex()
            digest_b = module.f_sponge(
                message_b, rate, rounds, digest_bits
            ).hex()
            expected_a, expected_b = EXPECTED[(name, "megascon")]
            assert message_a != message_b
            assert (digest_a, digest_b) == (expected_a, expected_b)
            assert digest_a != digest_b
            print(implementation, name, digest_a, digest_b, "distinct")


if __name__ == "__main__":
    main()
