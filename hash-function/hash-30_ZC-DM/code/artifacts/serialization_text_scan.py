#!/usr/bin/env python3
"""Reproduce the literal serialization-term scan of the ZC-DM specification."""

from __future__ import annotations

import re
import sys
from pathlib import Path

from pypdf import PdfReader


def main() -> None:
    pdf = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("hash-30-spec.pdf")
    terms = (
        "serialization",
        "byte order",
        "bit order",
        "little-endian",
        "big-endian",
        "test vector",
        "lexic",
        "total order",
        "leading",
        "least significant bit",
    )
    reader = PdfReader(pdf)
    pages = [" ".join((page.extract_text() or "").split()) for page in reader.pages]

    print(f"pdf={pdf}")
    print(f"pages={len(pages)}")
    for term in terms:
        pattern = re.compile(re.escape(term), re.IGNORECASE)
        hits = [
            (number, len(pattern.findall(text)))
            for number, text in enumerate(pages, 1)
            if pattern.search(text)
        ]
        print(f"{term!r}: {hits}")


if __name__ == "__main__":
    main()
