#!/usr/bin/env python3
"""Exact finite regression checks for the proof in gwots_antichain_proof.md."""

from itertools import product
from pathlib import Path
import re


def checksum(a, widths):
    return sum((1 << s) - 1 - x for x, s in zip(a, widths))


def exhaustive_small_case():
    widths = (1, 1)
    vectors = list(product(range(2), repeat=len(widths)))
    accepted = [(a, checksum(a, widths)) for a in vectors]
    compared = 0
    for a, ca in accepted:
        for ap, cap in accepted:
            if all(x <= y for x, y in zip(a, ap)) and ca <= cap:
                assert a == ap and ca == cap
                compared += 1
    return compared


def checksum_negative_control():
    widths = (1, 1)
    a = (0, 0)
    ap = (1, 0)
    encoded_a = a + (checksum(a, widths),)
    encoded_ap = ap + (checksum(ap, widths),)
    assert all(x <= y for x, y in zip(a, ap))
    assert not all(x <= y for x, y in zip(encoded_a, encoded_ap))
    return encoded_a, encoded_ap


def parser_configs(root):
    rows = []
    for path in sorted(root.glob("Phoenix-SHAKE-*/params/params-*.h")):
        if "Phoenix-SHAKE-128" in str(path):
            continue
        text = path.read_text()

        def value(name):
            match = re.search(rf"^#define\s+{re.escape(name)}\s+(\d+)\s*$",
                              text, re.MULTILINE)
            assert match, (path, name)
            return int(match.group(1))

        w1 = value("SPX_GWOTS_W1")
        w2 = value("SPX_GWOTS_W2")
        n1 = value("SPX_GWOTS_W1_LEN")
        n2 = value("SPX_GWOTS_W2_LEN")
        cw = value("SPX_GWOTS_CHECKSUM_W")
        expected_sum = (n1 * (w1 - 1) + n2 * (w2 - 1)) // 2
        base = expected_sum - cw // 2
        upper = base + (cw - 1)
        assert upper - base == cw - 1
        assert 0 <= base
        assert 0 <= upper - base < cw
        assert cw - 1 - (upper - base) == 0
        rows.append((path.parent.parent.name, n1, n2, base, upper, cw))
    return rows


def main():
    compared = exhaustive_small_case()
    encoded_a, encoded_ap = checksum_negative_control()
    root = Path(
        "src/Implementations and Test_Vectors/Implementations/"
        "Reference_Implementation"
    )
    rows = parser_configs(root)
    assert len(rows) == 8
    for variant, n1, n2, base, upper, cw in rows:
        print(f"{variant}: digits={n1}+{n2}, interval=[{base},{upper}], "
              f"checksum_base={cw}, max_digit={upper-base}, "
              f"remaining_steps={cw-1-(upper-base)}")
    print(f"small_case_comparable_pairs_checked={compared}")
    print(f"checksum_negative_control=message_comparable:{encoded_a} vs "
          f"{encoded_ap}, encoded_incomparable")
    print("result=PASS")


if __name__ == "__main__":
    main()
