#!/usr/bin/env python3
"""Exact A/B digest divergence from the same published Appendix-B IV.

This models the important interoperability scenario where an implementation
accepts Appendix B's H(0) as a precomputed constant, so choosing A or B cannot
diverge at initialization.  The first processed block still selects each
layout's permutation.
"""

from __future__ import annotations

import hashlib

import verify_juzi as v
from verify_empty_digests import digest, pad_empty_message, process_block


def empty_digest_from_published_iv(size: int, layout: str) -> bytes:
    published = v.PUBLISHED_512 if size == 512 else v.PUBLISHED_1024
    state = process_block(published, pad_empty_message(), size, layout)
    return digest(state, size)


def main() -> int:
    ok = True
    for size in (512, 1024):
        a = empty_digest_from_published_iv(size, "A")
        b = empty_digest_from_published_iv(size, "B")
        equal_bytes = sum(x == y for x, y in zip(a, b))
        differing_bits = sum((x ^ y).bit_count() for x, y in zip(a, b))
        print(f"{size}/A sha256={hashlib.sha256(a).hexdigest()}")
        print(f"{size}/B sha256={hashlib.sha256(b).hexdigest()}")
        print(f"{size}/A digest={a.hex()}")
        print(f"{size}/B digest={b.hex()}")
        print(
            f"{size}/A-vs-B equal={a == b} equal_bytes={equal_bytes}/{len(a)} "
            f"differing_bits={differing_bits}"
        )
        ok &= a != b
    print(f"VERDICT: different_empty_digests_from_same_IV_for_both={ok}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
