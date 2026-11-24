#!/usr/bin/env python3
import argparse
import json
from pathlib import Path


FIELDS = ("PK", "SK", "CT", "SS")


def parse_record(path: Path):
    values = {}
    lengths = {}
    count = None
    for raw in path.read_text(encoding="ascii").splitlines():
        line = raw.strip()
        if line.startswith("Count ="):
            count = int(line.split("=", 1)[1])
            continue
        for field in (*FIELDS, "Seed"):
            if line.startswith(f"{field}_Len ="):
                lengths[field] = int(line.split("=", 1)[1])
            elif line.startswith(f"{field} ="):
                values[field] = bytes.fromhex(line.split("=", 1)[1].strip())
        if count == 0 and all(field in values for field in FIELDS):
            return count, lengths, values
    raise RuntimeError(f"incomplete first record in {path}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("kat", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    count, lengths, values = parse_record(args.kat)
    args.output.mkdir(parents=True, exist_ok=True)
    manifest = {"source": str(args.kat), "count": count, "files": {}}
    for field, value in values.items():
        path = args.output / f"{field.lower()}.bin"
        path.write_bytes(value)
        manifest["files"][field] = {
            "path": str(path),
            "bytes": len(value),
            "declared_bytes": lengths.get(field),
            "sha256": __import__("hashlib").sha256(value).hexdigest(),
        }
    (args.output / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(manifest, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
