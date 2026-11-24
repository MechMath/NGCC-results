#!/usr/bin/env python3
import sys
from pathlib import Path

MODE = {
    "128": {"n": 512, "l": 2, "chunk_bits": 57, "low_bits": 24},
    "256": {"n": 512, "l": 3, "chunk_bits": 65, "low_bits": 32},
}
BASE = 17
DIGITS = 8
BASE_SPACE = BASE ** DIGITS


def get_bits(data: bytearray, start: int, count: int) -> int:
    value = 0
    for i in range(count):
        bit = start + i
        value |= ((data[bit // 8] >> (bit % 8)) & 1) << i
    return value


def set_bits(data: bytearray, start: int, count: int, value: int) -> None:
    for i in range(count):
        bit = start + i
        mask = 1 << (bit % 8)
        if (value >> i) & 1:
            data[bit // 8] |= mask
        else:
            data[bit // 8] &= ~mask


def main() -> int:
    if len(sys.argv) != 4 or sys.argv[1] not in MODE:
        print(f"usage: {sys.argv[0]} <128|256> <input-signature> "
              "<output-signature>",
              file=sys.stderr)
        return 64

    mode = MODE[sys.argv[1]]
    n = mode["n"]
    chunk_bits = mode["chunk_bits"]
    low_bits = mode["low_bits"]
    base_bit_count = chunk_bits - low_bits
    packed_space = 1 << base_bit_count

    src = bytearray(Path(sys.argv[2]).read_bytes())
    low_start = (n // 8) * 8
    chosen = None

    for chunk in range(n // 8):
        start = low_start + chunk * chunk_bits
        packed = get_bits(src, start, chunk_bits)
        base17_value = packed >> low_bits
        new_value = base17_value + BASE_SPACE
        if new_value >= packed_space:
            continue
        chosen = (chunk, start, base17_value, new_value)
        set_bits(src, start + low_bits, base_bit_count, new_value)
        break

    if chosen is None:
        print("no chunk admitted the ignored-quotient mutation", file=sys.stderr)
        return 1

    Path(sys.argv[3]).write_bytes(src)
    print("chunk=%d old_base17=%d new_base17=%d ignored_quotient_increment=1"
          % (chosen[0], chosen[2], chosen[3]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
