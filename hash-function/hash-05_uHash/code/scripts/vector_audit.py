#!/usr/bin/env python3
"""Audit digest widths and accidental suffix duplication in PDF test vectors."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PDF = ROOT / "source" / "hash-05-spec.pdf"
TEXT = ROOT / "source" / "hash-05-spec.txt"
OUT = ROOT / "artifacts" / "vector_audit.json"


def clean_lines() -> list[str]:
    lines = []
    for line in TEXT.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if re.fullmatch(r"\d+", stripped):
            continue
        if re.fullmatch(r"\d+\s+Cryptographic Hash Algorithm uHash", stripped):
            continue
        if stripped.startswith("Yafei Zheng"):
            continue
        if stripped.startswith("===== PAGE"):
            continue
        lines.append(stripped)
    return lines


def audit() -> dict:
    lines = clean_lines()

    def section_start(prefix: str) -> int:
        return max(i for i, line in enumerate(lines) if line.startswith(prefix))

    starts = {
        512: section_start("8.1  Test Vectors of uHash-512"),
        768: section_start("8.2  Test Vectors of uHash-768"),
        1024: section_start("8.3  Test Vectors of uHash-1024"),
    }
    end = next(i for i, line in enumerate(lines) if line == "References")
    sections = {
        512: lines[starts[512]:starts[768]],
        768: lines[starts[768]:starts[1024]],
        1024: lines[starts[1024]:end],
    }
    records = []
    for bits, section in sections.items():
        example_starts = [i for i, line in enumerate(section)
                          if re.fullmatch(r"• Example \d+:", line)]
        example_starts.append(len(section))
        for left, right in zip(example_starts, example_starts[1:]):
            block = section[left:right]
            number = int(re.search(r"\d+", block[0]).group())
            declared = int(next(re.search(r"\d+", line).group()
                                for line in block if line.startswith("Dst_Len =")))
            dst_at = block.index("Dst =")
            digest_lines = []
            for line in block[dst_at + 1:]:
                if re.fullmatch(r"[0-9A-Fa-f]+", line):
                    digest_lines.append(line)
                else:
                    break
            digest = "".join(digest_lines).upper()
            records.append({
                "variant": f"uHash-{bits}",
                "declared_digest_bits": declared,
                "digest_hex": digest,
                "actual_hex_characters": len(digest),
                "actual_bits": 4 * len(digest),
                "valid_hex": bool(re.fullmatch(r"[0-9A-F]+", digest)),
                "width_matches": declared == 4 * len(digest),
                "example": number,
            })

    contaminated = next(r for r in records
                        if r["variant"] == "uHash-512" and r["example"] == 4)
    previous = next(r for r in records
                    if r["variant"] == "uHash-512" and r["example"] == 3)
    tail = contaminated["digest_hex"]
    previous_hex = previous["digest_hex"]
    overlap = 0
    for size in range(1, min(len(tail), len(previous_hex)) + 1):
        if tail[-size:] == previous_hex[-size:]:
            overlap = size
    result = {
        "input": {
            "pdf": str(PDF.relative_to(ROOT)),
            "pdf_sha256": hashlib.sha256(PDF.read_bytes()).hexdigest(),
            "extracted_text": str(TEXT.relative_to(ROOT)),
            "extracted_text_sha256": hashlib.sha256(TEXT.read_bytes()).hexdigest(),
        },
        "vectors": records,
        "width_failures": [r for r in records if not r["width_matches"]],
        "uHash512_example4_suffix_overlap_with_example3_hex_chars": overlap,
        "uHash512_example4_prefix_at_declared_width": contaminated["digest_hex"][:128],
        "interpretation_limits": (
            "This audits only the literal lengths and byte strings printed in Section 8. "
            "It neither implements the cipher nor establishes a cryptographic attack."
        ),
    }
    return result


def main() -> None:
    result = audit()
    OUT.parent.mkdir(exist_ok=True)
    OUT.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
