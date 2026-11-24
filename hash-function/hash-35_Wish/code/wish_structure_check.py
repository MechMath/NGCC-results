#!/usr/bin/env python3
"""Independent structural checks for the pinned Wish v1.0 specification.

The only input document used is hash-35-spec.pdf from the permitted hash-35 URL.
This script reconstructs the printed butterfly map from its stated granularities and
checks bijectivity, Properties 4.1--4.4 (including ShiftRows for 4.1--4.3), and the
claimed stage sets. It also parses Eqs. (2)--(3) from the PDF text so that the printed
tables, rather than the reconstruction, are tested.
"""

from __future__ import annotations

import re
import sys
import itertools

import pymupdf


def interleave_low(a: list[int], b: list[int], g: int) -> list[int]:
    out: list[int] = []
    for start in range(0, 8, g):
        out.extend(a[start : start + g])
        out.extend(b[start : start + g])
    return out


def interleave_high(a: list[int], b: list[int], g: int) -> list[int]:
    out: list[int] = []
    for start in range(8, 16, g):
        out.extend(a[start : start + g])
        out.extend(b[start : start + g])
    return out


def butterfly(lanes: int, granularities: tuple[int, ...]) -> list[int]:
    state = [list(range(16 * i, 16 * (i + 1))) for i in range(lanes)]
    for j, g in enumerate(granularities):
        nxt = [None] * lanes
        for i in range(lanes):
            q = i ^ (1 << j)
            if i < q:
                nxt[i] = interleave_low(state[i], state[q], g)
                nxt[q] = interleave_high(state[i], state[q], g)
        state = nxt
    return [x for lane in state for x in lane]


def inverse_permutation(sigma: list[int]) -> list[int]:
    inv = [None] * len(sigma)
    for i, x in enumerate(sigma):
        assert inv[x] is None
        inv[x] = i
    return inv


def shift_rows_position(i: int) -> int:
    r, c = i % 4, i // 4
    return r + 4 * ((c - r) % 4)


def shift_rows_permutation(sigma: list[int]) -> list[int]:
    # ShiftRows maps pre-SR index x to post-SR index x-r+4r, i.e. pre-index
    # r+4((c-r) mod 4) maps to post-index 4c+r. Compose SR after sigma.
    out = [None] * len(sigma)
    for i, src in enumerate(sigma):
        lane, within = divmod(i, 16)
        r, c = within % 4, within // 4
        post = lane * 16 + 4 * ((c + r) % 4) + r
        out[post] = src
    assert sorted(out) == list(range(len(sigma)))
    return out


def properties(sigma: list[int], lanes: int) -> dict[str, bool]:
    i2l = lambda i: i // 16
    # Sections 2 and 3.2 define columns globally: every four consecutive state
    # bytes form a column. A lane is four such columns.
    i2c = lambda i: i // 4
    p41 = True
    for j in range(lanes):
        for k in range(lanes):
            p41 &= sum(i2l(sigma[16 * j + t]) == k for t in range(16)) == 16 // lanes
    p42 = all(len({i2c(sigma[4 * j + t]) for t in range(4)}) == 4 for j in range(lanes * 4))
    p43 = all(len({i2l(sigma[4 * j + t]) for t in range(4)}) >= 2 for j in range(lanes * 4))
    return {
        "4.1_Mix": all(
            sum(i2l(sigma[16 * j + t]) == k for t in range(16)) == 16 // lanes
            for j in range(lanes)
            for k in range(lanes)
        ),
        "4.2_Mix": p42,
        "4.3_Mix": p43,
    }


def p42_witnesses(sigma: list[int], lanes: int) -> list[tuple[int, list[int], list[int]]]:
    witnesses = []
    for col in range(4 * lanes):
        sources = [sigma[4 * col + t] for t in range(4)]
        source_cols = [i // 4 for i in sources]
        if len(set(source_cols)) != 4:
            witnesses.append((col, sources, source_cols))
    return witnesses


def truncation(sigma_inv: list[int], lanes: int) -> tuple[bool, list[int]]:
    # H is the capacity (second half of the post-Mix state). For each post-Mix
    # column, count input positions in its inverse image that lie in the rate.
    retained_cols = range(lanes * 2, lanes * 4)
    counts = []
    for col in retained_cols:
        image = [sigma_inv[4 * col + t] for t in range(4)]
        counts.append(sum(x < 8 * lanes for x in image))
    return all(x >= 1 for x in counts), counts


def parse_printed(page_text: str, label: str, end_label: str) -> list[int]:
    body = page_text.split(label, 1)[1].split(end_label, 1)[0]
    nums = [int(x) for x in re.findall(r"(?<![A-Za-z0-9])(?:[0-9]|[1-9][0-9]{1,2})(?![A-Za-z0-9])", body)]
    return nums


def main() -> None:
    doc = pymupdf.open("hash-35-spec.pdf")
    text = doc[5].get_text("text")
    printed = {
        8: parse_printed(text, "Mix1024 =", ",\n(2)"),
        16: parse_printed(text, "Mix2048 =", ".\n(3)"),
    }
    granularities = {8: (1, 2, 8), 16: (1, 2, 4, 8)}
    all_ok = True
    for lanes in (8, 16):
        expected = butterfly(lanes, granularities[lanes])
        actual = printed[lanes]
        print(f"lanes={lanes} printed_count={len(actual)}")
        if actual != expected:
            all_ok = False
            diffs = [(i, a, e) for i, (a, e) in enumerate(zip(actual, expected)) if a != e]
            print("PRINTED_TABLE_MISMATCH", diffs[:20])
        else:
            print("printed table exactly equals reconstruction")
        inv = inverse_permutation(expected)
        fwd_sr = shift_rows_permutation(expected)
        for name, sig in (
            ("MixInv", inv),
            ("ShiftRows_after_Mix", fwd_sr),
        ):
            p = properties(sig, lanes)
            print(name, p)
            witnesses42 = p42_witnesses(sig, lanes)
            print(name, "first Property4.2 witness", witnesses42[0] if witnesses42 else None)
            all_ok &= all(p.values())
        ok, counts = truncation(inv, lanes)
        print("MixInv truncation", ok, counts)
        all_ok &= ok
    # Enumerate the exact finite search space stated in Section 4.2.3 under the
    # literal byte/column definitions from Sections 2 and 3.2. Properties 4.1--
    # 4.3 must hold for sigma_fwd=ShiftRows o Mix and sigma_bwd=Mix^{-1}; the
    # strengthened Property 4.4 is checked on Mix^{-1}.
    for lanes in (8, 16):
        survivors = []
        details = {}
        for gs in itertools.product((1, 2, 4, 8), repeat=(3 if lanes == 8 else 4)):
            m = butterfly(lanes, gs)
            inv = inverse_permutation(m)
            fwd = shift_rows_permutation(m)
            pf = properties(fwd, lanes)
            pb = properties(inv, lanes)
            trunc_ok, trunc_counts = truncation(inv, lanes)
            key = tuple(sorted({**pf, **pb}.items())) + (("4.4", trunc_ok),)
            details[key] = details.get(key, 0) + 1
            if all(pf.values()) and all(pb.values()) and trunc_ok and set(trunc_counts) == {2}:
                survivors.append(gs)
        print(f"lanes={lanes} literal_search_survivors={len(survivors)}")
        print("survivors", survivors[:30])
        for k, count in sorted(details.items(), key=lambda kv: str(kv[0])):
            print(f"  profile_count={count}: {k}")
        all_ok &= bool(survivors)
    print("ALL_CHECKS_PASS" if all_ok else "CHECK_FAILURE")
    sys.exit(0 if all_ok else 1)


if __name__ == "__main__":
    main()
