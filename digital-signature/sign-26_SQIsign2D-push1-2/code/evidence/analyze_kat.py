#!/usr/bin/env python3
"""Parse signatures KATs using the fixed NGCC harness's canonical text rule."""

from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path


def canonical_hash(raw: bytes, nolen: bool = False) -> str:
    lines = []
    for line in raw.splitlines():
        line = line.rstrip(b" \t\r")
        if not line:
            continue
        if nolen:
            eq = line.find(b"=")
            if eq >= 5 and line[:eq].rstrip().endswith(b"_Len"):
                continue
        lines.append(line)
    return hashlib.sha256(b"\n".join(lines) + b"\n").hexdigest()


def parse_manifest(path: Path) -> dict[str, dict[str, object]]:
    result = {}
    for line in path.read_text().splitlines():
        digest, mode, name = line.split()
        nolen, _, records = mode.partition(":")
        result[Path(name).name] = {
            "sha256": digest,
            "mode": nolen,
            "records": int(records) if records else None,
        }
    return result


def inspect(path: Path, manifest_entry: dict[str, object] | None) -> dict[str, object]:
    raw = path.read_bytes()
    records = re.findall(rb"^Count = (\d+)$", raw, flags=re.MULTILINE)
    sk_lens = [int(x) for x in re.findall(rb"^SK_Len = (\d+)$", raw, flags=re.MULTILINE)]
    pk_lens = [int(x) for x in re.findall(rb"^PK_Len = (\d+)$", raw, flags=re.MULTILINE)]
    sn_lens = [int(x) for x in re.findall(rb"^Sn_Len = (\d+)$", raw, flags=re.MULTILINE)]
    computed = canonical_hash(raw)
    expected = manifest_entry["sha256"] if manifest_entry else None
    return {
        "path": str(path),
        "raw_sha256": hashlib.sha256(raw).hexdigest(),
        "canonical_sha256": computed,
        "manifest_sha256": expected,
        "digest_match": computed == expected if expected else None,
        "bytes": len(raw),
        "record_count": len(records),
        "record_indices": [int(x) for x in records],
        "pk_lengths": sorted(set(pk_lens)),
        "sk_lengths": sorted(set(sk_lens)),
        "signature_lengths": sorted(set(sn_lens)),
    }


def main() -> int:
    if len(sys.argv) < 3:
        print(f"usage: {sys.argv[0]} MANIFEST KAT...", file=sys.stderr)
        return 2
    manifest = parse_manifest(Path(sys.argv[1]))
    output = []
    for name in sys.argv[2:]:
        path = Path(name)
        output.append(inspect(path, manifest.get(path.name)))
    print(json.dumps(output, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
