#!/usr/bin/env python3
import re
import struct
import sys
from pathlib import Path


def main() -> None:
    if len(sys.argv) != 4:
        raise SystemExit("usage: kat_to_bundle.py KAT OUTPUT COUNT")
    src, out, wanted = Path(sys.argv[1]), Path(sys.argv[2]), int(sys.argv[3])
    entries = []
    current = {}
    for raw in src.read_text(encoding="ascii").splitlines():
        m = re.match(r"^([A-Za-z_]+)\s*=\s*(.*)$", raw)
        if not m:
            continue
        key, value = m.groups()
        if key == "Count":
            if current:
                entries.append(current)
            current = {"Count": int(value)}
        else:
            current[key] = value
    if current:
        entries.append(current)
    e = entries[wanted]
    pk = bytes.fromhex(e["PK"])
    sig = bytes.fromhex(e["Sn"])
    msg = bytes.fromhex(e["M"])
    assert len(pk) == int(e["PK_Len"])
    assert len(sig) == int(e["Sn_Len"])
    assert len(msg) == int(e["M_Len"])
    out.write_bytes(struct.pack("<QQQ", len(pk), len(sig), len(msg)) + pk + sig + msg)
    print(f"count={wanted} pk={len(pk)} sig={len(sig)} msg={len(msg)} output={out}")


if __name__ == "__main__":
    main()
