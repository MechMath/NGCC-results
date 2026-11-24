#!/usr/bin/env python3
"""Extract the pinned Thunder specification with page delimiters."""

from pathlib import Path

from pypdf import PdfReader


def main() -> None:
    pdf_path = Path("thunder-hash-33-spec.pdf")
    out_path = Path("thunder-hash-33-spec.txt")
    reader = PdfReader(pdf_path)
    with out_path.open("w", encoding="utf-8") as out:
        out.write(f"SOURCE_SHA256={__import__('hashlib').sha256(pdf_path.read_bytes()).hexdigest()}\n")
        out.write(f"PAGES={len(reader.pages)}\n")
        for page_number, page in enumerate(reader.pages, start=1):
            out.write(f"\n===== PAGE {page_number} =====\n")
            out.write(page.extract_text() or "")
            out.write("\n")


if __name__ == "__main__":
    main()
