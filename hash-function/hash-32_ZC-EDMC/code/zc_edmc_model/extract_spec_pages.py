#!/usr/bin/env python3
"""Extract the assigned pages from the allowlisted local specification."""

from pathlib import Path

from pypdf import PdfReader


ROOT = Path(__file__).resolve().parent
PDF = ROOT / "input" / "hash-32-spec.pdf"
OUT = ROOT / "input" / "pages-05-15.txt"


def main() -> None:
    reader = PdfReader(PDF)
    if len(reader.pages) < 15:
        raise SystemExit(f"expected at least 15 pages, found {len(reader.pages)}")
    chunks = []
    for page_number in range(5, 16):
        text = reader.pages[page_number - 1].extract_text() or ""
        chunks.append(f"\n===== PDF PAGE {page_number} =====\n{text}")
    OUT.write_text("".join(chunks), encoding="utf-8")
    print(f"extracted pages 5-15 from {len(reader.pages)} pages to {OUT}")


if __name__ == "__main__":
    main()
