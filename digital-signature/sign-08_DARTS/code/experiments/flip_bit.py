#!/usr/bin/env python3
import sys
from pathlib import Path


def main() -> int:
    if len(sys.argv) != 4:
        print(f"usage: {sys.argv[0]} <input> <output> <zero-based-byte-index>",
              file=sys.stderr)
        return 64
    data = bytearray(Path(sys.argv[1]).read_bytes())
    index = int(sys.argv[3])
    data[index] ^= 1
    Path(sys.argv[2]).write_bytes(data)
    print(f"flipped_bit=byte[{index}]&1")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
