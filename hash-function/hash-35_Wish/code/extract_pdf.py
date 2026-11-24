#!/usr/bin/env python3
"""Extract the pinned PDF text with explicit PDF-page delimiters."""

from pathlib import Path

from pypdf import PdfReader


def main() -> None:
    source = Path("hash-35-spec.pdf")
    reader = PdfReader(source)
    chunks = []
    for page_number, page in enumerate(reader.pages, start=1):
        text = page.extract_text(extraction_mode="layout") or ""
        chunks.append(f"\n===== PDF PAGE {page_number} =====\n{text}")
    Path("hash-35-spec-extracted.txt").write_text(
        "".join(chunks), encoding="utf-8"
    )
    print(f"pages={len(reader.pages)} bytes={sum(len(c) for c in chunks)}")


if __name__ == "__main__":
    main()
