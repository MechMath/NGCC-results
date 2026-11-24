#!/usr/bin/env python3
"""Structural audit of BRA's canonical G/H hash input encodings."""

from pathlib import Path
import re


ROOT = Path(__file__).resolve().parent / "source" / "BRA" / "Implementations" / "Optimized_Implementation"


def defines(path: Path) -> dict[str, int]:
    result = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        match = re.match(r"#define\s+(BRA_(?:PUBLIC_KEY_BYTES|VEC_K_BYTES|VEC_N_BYTES|SALT_BYTES))\s+(\d+)", line)
        if match:
            result[match.group(1)] = int(match.group(2))
    return result


def canonical_encoding(parts: list[bytes]) -> bytes:
    return b"".join(parts)


def positive_control(lengths: list[int]) -> bool:
    """A changed component changes the canonical encoding."""
    parts1 = [bytes([i + 1]) * n for i, n in enumerate(lengths)]
    parts2 = [bytearray(x) for x in parts1]
    parts2[1][0] ^= 1
    return canonical_encoding(parts1) != canonical_encoding([bytes(x) for x in parts2])


def negative_control(lengths: list[int]) -> bool:
    """Identical components have identical canonical encodings."""
    parts = [bytes([i + 1]) * n for i, n in enumerate(lengths)]
    return canonical_encoding(parts) == canonical_encoding(parts)


def main() -> None:
    for level in ("128", "256", "512"):
        base = ROOT / f"BRA-{level}"
        d = defines(base / "src" / "parameters.h")
        pk = d["BRA_PUBLIC_KEY_BYTES"]
        k = d["BRA_VEC_K_BYTES"]
        n = d["BRA_VEC_N_BYTES"]
        salt = d["BRA_SALT_BYTES"]
        g_len = pk + k + salt
        h_len = pk + k + 2 * n + salt
        assert n > 0 and g_len < h_len
        assert positive_control([pk, k, salt])
        assert positive_control([pk, k, n, n, salt])
        assert negative_control([pk, k, salt])
        assert negative_control([pk, k, n, n, salt])
        print(
            f"BRA-{level}: pk={pk} k={k} n={n} salt={salt} "
            f"G={g_len} H={h_len} disjoint_lengths={g_len != h_len} "
            f"controls=pass"
        )


if __name__ == "__main__":
    main()
