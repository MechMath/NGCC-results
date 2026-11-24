#!/usr/bin/env python3
"""Cross-check full JuziHash digests against the exploratory checker.

The primary implementation and its first outputs were sealed before this
checker was inspected. This wrapper reuses only the exploratory checker's
primitive operations, adds Appendix 4's padding/update/projection wrapper, and
compares every digest with juzihash-repro.json.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path


def load_exploratory(path: Path):
    module_spec = importlib.util.spec_from_file_location("verify_juzi", path)
    if module_spec is None or module_spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(module_spec)
    module_spec.loader.exec_module(module)
    return module


def pad_message(message: bytes) -> bytes:
    bit_length = 8 * len(message)
    zero_bits = (-bit_length) % 1024
    return (
        message
        + bytes(zero_bits // 8)
        + bytes(120)
        + bit_length.to_bytes(8, "big")
    )


def inject_message(state: bytes, block: bytes) -> bytes:
    output = bytearray(state)
    for word, offset in ((0, 0), (1, 32), (4, 64), (5, 96)):
        for position in range(32):
            output[32 * word + position] ^= block[offset + position]
    return bytes(output)


def run_hash(module, message: bytes, bits: int, which: str, initial: bytes) -> bytes:
    padded = pad_message(message)
    state = initial
    for offset in range(0, len(padded), 128):
        injected = inject_message(state, padded[offset : offset + 128])
        permuted = module.permute(injected, which)[0]
        state = permuted if bits == 512 else module.update_1024(state, permuted)
    if bits == 512:
        return state[:64]
    return state[64:128] + state[192:256]


def main() -> None:
    root = Path(__file__).resolve().parent
    exploratory_path = root.parent / "139645e14a424bbc" / "verify_juzi.py"
    observed_path = root / "juzihash-repro.json"
    module = load_exploratory(exploratory_path)
    observed = json.loads(observed_path.read_text(encoding="utf-8"))
    published = {512: module.PUBLISHED_512, 1024: module.PUBLISHED_1024}

    comparisons = {}
    all_equal = True
    for label, message in (("empty", b""), ("abc", b"abc")):
        for bits in (512, 1024):
            for which, mode in (
                ("A", "changing_dimension"),
                ("B", "fixed_word"),
            ):
                digest = run_hash(module, message, bits, which, published[bits])
                expected = observed["messages"][label]["implementations"][mode][
                    f"JuziHash-{bits}"
                ]["digest_hex"]
                equal = digest.hex() == expected
                all_equal &= equal
                comparisons[f"{label}/{bits}/{which}"] = {
                    "equal": equal,
                    "digest_sha256": hashlib.sha256(digest).hexdigest(),
                }

    result = {
        "schema": "juzihash-exploratory-full-digest-crosscheck-v1",
        "exploratory_source": str(exploratory_path),
        "exploratory_sha256": hashlib.sha256(
            exploratory_path.read_bytes()
        ).hexdigest(),
        "observed_json_sha256_at_crosscheck_time": hashlib.sha256(
            observed_path.read_bytes()
        ).hexdigest(),
        "comparisons": comparisons,
        "all_equal": all_equal,
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    if not all_equal:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
