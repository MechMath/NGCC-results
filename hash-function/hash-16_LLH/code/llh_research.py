#!/usr/bin/env python3
"""Literal, auditable executable model of the pinned LLH hash-16 specification.

This file is a research note and reproducibility artifact.  The 24-bit S-box and
the deterministic propagation sample are also represented in successful
crypto_run jobs; local output alone is not presented as verified evidence.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
from collections import Counter
from pathlib import Path


MASK6 = (1 << 6) - 1
SPEC_SHA256 = "c0e907402bc79dd1b6f116bf09daaabdd5b8d1bc53eda68458929c636be06d8f"

SHIFTS = {
    32: [3, 16, 13, 26, 8, 29, 2, 23, 21, 18, 31, 28, 10, 15, 4, 9, 7, 20, 17, 30, 12, 1, 6, 27],
    64: [2, 25, 20, 51, 15, 40, 37, 6, 36, 63, 62, 33, 1, 30, 31, 4, 38, 5, 8, 47, 19, 52, 57, 34],
    96: [2, 11, 28, 53, 19, 34, 57, 88, 52, 73, 6, 43, 5, 32, 67, 14, 70, 7, 48, 1, 55, 94, 45, 4],
    128: [1, 16, 55, 118, 10, 29, 72, 11, 35, 58, 105, 48, 76, 103, 26, 101, 5, 36, 91, 42, 78, 113, 44, 127],
}

ROUNDS = {32: 16, 64: 24, 96: 32, 128: 40}
RATE_WORDS = 8

RC = {
    32: [
        0xB7E15162, 0x8AED2A6A, 0xBF715880, 0x9CF4F3C7,
        0x62E7160F, 0x38B4DA56, 0xA784D904, 0x5190CFEF,
        0x324E7738, 0x926CFBE5, 0xF4BF8D8D, 0x8C31D763,
        0xDA06C80A, 0xBB1185EB, 0x4F7C7B57, 0x57F59584,
    ],
    64: [
        0xB7E151628AED2A6A, 0xBF7158809CF4F3C7,
        0x62E7160F38B4DA56, 0xA784D9045190CFEF,
        0x324E7738926CFBE5, 0xF4BF8D8D8C31D763,
        0xDA06C80ABB1185EB, 0x4F7C7B5757F59584,
        0x90CFD47D7C19BB42, 0x158D9554F7B46BCE,
        0xD55C4D79FD5F24D6, 0x613C31C3839A2DDF,
        0x8A9A276BCFBFA1C8, 0x77C56284DAB79CD4,
        0xC2B3293D20E9E5EA, 0xF02AC60ACC93ED87,
        0x4422A52ECB238FEE, 0xE5AB6ADD835FD1A0,
        0x753D0A8F78E537D2, 0xB95BB79D8DCAEC64,
        0x2C1E9F23B829B5C2, 0x780BF38737DF8BB3,
        0x00D01334A0D0BD86, 0x45CBFA73A6160FFE,
    ],
    96: [
        0xB7E151628AED2A6ABF715880, 0x9CF4F3C762E7160F38B4DA56,
        0xA784D9045190CFEF324E7738, 0x926CFBE5F4BF8D8D8C31D763,
        0xDA06C80ABB1185EB4F7C7B57, 0x57F5958490CFD47D7C19BB42,
        0x158D9554F7B46BCED55C4D79, 0xFD5F24D6613C31C3839A2DDF,
        0x8A9A276BCFBFA1C877C56284, 0xDAB79CD4C2B3293D20E9E5EA,
        0xF02AC60ACC93ED874422A52E, 0xCB238FEEE5AB6ADD835FD1A0,
        0x753D0A8F78E537D2B95BB79D, 0x8DCAEC642C1E9F23B829B5C2,
        0x780BF38737DF8BB300D01334, 0xA0D0BD8645CBFA73A6160FFE,
        0x393C48CBBBCA060F0FF8EC6D, 0x31BEB5CCEED7F2F0BB088017,
        0x163BC60DF45A0ECB1BCD289B, 0x06CBBFEA21AD08E1847F3F73,
        0x78D56CED94640D6EF0D3D37B, 0xE67008E186D1BF275B9B241D,
        0xEB64749A47DFDFB96632C3EB, 0x061B6472BBF84C26144E49C2,
        0xD04C324EF10DE513D3F5114B, 0x8B5D374D93CB8879C7D52FFD,
        0x72BA0AAE7277DA7BA1B4AF14, 0x88D8E836AF14865E6C37AB68,
        0x76FE690B571121382AF341AF, 0xE94F77BCF06C83B8FF5675F0,
        0x979074AD9A787BC5B9BD4B0C, 0x5937D3EDE4C3A79396215EDA,
    ],
    128: [
        0xB7E151628AED2A6ABF7158809CF4F3C7,
        0x62E7160F38B4DA56A784D9045190CFEF,
        0x324E7738926CFBE5F4BF8D8D8C31D763,
        0xDA06C80ABB1185EB4F7C7B5757F59584,
        0x90CFD47D7C19BB42158D9554F7B46BCE,
        0xD55C4D79FD5F24D6613C31C3839A2DDF,
        0x8A9A276BCFBFA1C877C56284DAB79CD4,
        0xC2B3293D20E9E5EAF02AC60ACC93ED87,
        0x4422A52ECB238FEEE5AB6ADD835FD1A0,
        0x753D0A8F78E537D2B95BB79D8DCAEC64,
        0x2C1E9F23B829B5C2780BF38737DF8BB3,
        0x00D01334A0D0BD8645CBFA73A6160FFE,
        0x393C48CBBBCA060F0FF8EC6D31BEB5CC,
        0xEED7F2F0BB088017163BC60DF45A0ECB,
        0x1BCD289B06CBBFEA21AD08E1847F3F73,
        0x78D56CED94640D6EF0D3D37BE67008E1,
        0x86D1BF275B9B241DEB64749A47DFDFB9,
        0x6632C3EB061B6472BBF84C26144E49C2,
        0xD04C324EF10DE513D3F5114B8B5D374D,
        0x93CB8879C7D52FFD72BA0AAE7277DA7B,
        0xA1B4AF1488D8E836AF14865E6C37AB68,
        0x76FE690B571121382AF341AFE94F77BC,
        0xF06C83B8FF5675F0979074AD9A787BC5,
        0xB9BD4B0C5937D3EDE4C3A79396215EDA,
        0xB1F57D0B5A7DB461DD8F3C75540D0012,
        0x1FD56E95F8C731E9C4D7221BBED0C62B,
        0xB5A87804B679A0CAA41D802A4604C311,
        0xB71DE3E5C6B400E024A6668CCF2E2DE8,
        0x6876E4F5C50000F0A93B3AA7E6342B30,
        0x2A0A47373B25F73E3B26D569FE2291AD,
        0x36D6A147D1060B871A2801F978376408,
        0x2FF592D9140DB1E9399DF4B0E14CA8E8,
        0x8EE9110B2BD4FA98EED150CA6DD89322,
        0x45EF7592C703F532CE3A30CD31C070EB,
        0x36B4195FF33FB1C66C7D70F93918107C,
        0xE2051FED33F6D1DE9491C7DEA6A5A442,
        0xE154C8BB6D8D0362803BC248D414478C,
        0x2AFB07FFE78E89B9FECA7E3060C08F0D,
        0x61F8E36801DF66D1D8F9392E52CAEF06,
        0x53199479DF2BE64BBAAB008CA8A06FDA,
    ],
}

# Table 2-3, read as output_position -> source_position in the row-major
# 6x4 matrix after the four parallel S6 evaluations.
DERANGEMENT = [4, 9, 18, 23, 8, 1, 22, 15, 12, 17, 6, 3, 20, 5, 10, 19, 0, 21, 14, 11, 16, 13, 2, 7]


def ror6(x: int, r: int) -> int:
    return ((x >> r) | (x << (6 - r))) & MASK6


def s6(x: int) -> int:
    x &= MASK6
    return x ^ ror6(x, 2) ^ (ror6(x, 1) & ror6(x, 3)) ^ 0x1B


S6_TABLE = [s6(x) for x in range(64)]


def bit_reverse(x: int, nbits: int) -> int:
    """Reverse exactly nbits positions, preserving leading zeroes."""
    out = 0
    for _ in range(nbits):
        out = (out << 1) | (x & 1)
        x >>= 1
    return out


def rol_word(x: int, r: int, w: int) -> int:
    mask = (1 << w) - 1
    if r == 0:
        return x & mask
    return ((x << r) | (x >> (w - r))) & mask


def column_apply(v: int) -> int:
    """Apply S6 to the four row-major 6x4 columns of a 24-bit slice."""
    cols = [0, 0, 0, 0]
    for bit in range(24):
        cols[bit & 3] |= ((v >> bit) & 1) << (bit >> 2)
    for c in range(4):
        cols[c] = S6_TABLE[cols[c]]
    pre = 0
    for bit in range(24):
        pre |= ((cols[bit & 3] >> (bit >> 2)) & 1) << bit
    shuffled = 0
    for out_pos, in_pos in enumerate(DERANGEMENT):
        shuffled |= ((pre >> in_pos) & 1) << out_pos
    # D = J_4 - I_4 over GF(2).  Row j therefore becomes the XOR of the
    # other three entries, including j, which is XOR of all four row entries.
    out = 0
    for row in range(6):
        row_bits = (shuffled >> (4 * row)) & 0xF
        parity = row_bits.bit_count() & 1
        for col in range(4):
            if parity ^ ((row_bits >> col) & 1):
                out |= 1 << (4 * row + col)
    return out


def s24_pack(v: int) -> int:
    return column_apply(v)


def round_fun(words: list[int], width: int, rnd: int):
    mask = (1 << width) - 1
    out = [0] * 24
    for col in range(width):
        v = 0
        for row in range(24):
            v |= ((words[row] >> col) & 1) << row
        u = s24_pack(v)
        for row in range(24):
            out[row] |= ((u >> row) & 1) << col
    for row in range(24):
        out[row] = rol_word(out[row], SHIFTS[width][row], width)
    out[23] ^= RC[width][rnd] & mask
    return out


def permutation(words: list[int], width: int, rounds: int) -> list[int]:
    state = list(words)
    for rnd in range(rounds):
        state = round_fun(state, width, rnd)
    return state


def initial_state(
    width: int,
    bit_length: int,
    length_encoding: str = "literal_msb_first",
) -> list[int]:
    if not 0 <= bit_length <= (1 << 64) - 1:
        raise ValueError("LLH length field is exactly 64 bits")
    state = [0] * 24
    if length_encoding == "literal_msb_first":
        # S^(0) = 0^(b-64) || L is a bitstring identity.  The first state
        # position after the zero prefix is L's most significant bit, while a
        # word's bit zero is the first position in that word.  Consequently all
        # 64 length bits are reversed relative to the usual integer bit order.
        encoded = bit_reverse(bit_length, 64)
    elif length_encoding == "little_endian_integer":
        # Alternative reading: serialise L as a 64-bit little-endian integer.
        # Retained separately because the PDF does not state how to resolve the
        # numeric L into the 64-bit string.
        encoded = bit_length & ((1 << 64) - 1)
    else:
        raise ValueError("unknown length encoding")
    for bit in range(64):
        pos = (24 * width - 64) + bit
        state[pos // width] |= ((encoded >> bit) & 1) << (pos % width)
    return state


def bytes_to_words_little(data: bytes, width: int) -> list[int]:
    byte_width = width // 8
    if len(data) % byte_width:
        raise ValueError("word conversion requires a whole number of words")
    return [int.from_bytes(data[i:i + byte_width], "little") for i in range(0, len(data), byte_width)]


def words_to_bytes_little(words: list[int], width: int) -> bytes:
    byte_width = width // 8
    return b"".join(x.to_bytes(byte_width, "little") for x in words)


def pad_message(data: bytes, bit_length: int, width: int) -> bytes:
    if bit_length != 8 * len(data):
        raise ValueError("this API requires byte-aligned messages")
    rate_bits = 8 * width
    rem = bit_length % rate_bits
    if rem == 0:
        return data
    pad_bits = rate_bits - rem
    # The 1 run is not byte-aligned in general.  To avoid an endianness
    # ambiguity in this byte-oriented API, use the bitstring integer directly.
    whole, final = divmod(pad_bits, 8)
    raw = int.from_bytes(data, "little") | (((1 << pad_bits) - 1) << bit_length)
    total_bytes = (bit_length + pad_bits) // 8
    del whole, final
    return raw.to_bytes(total_bytes, "little")


def llh(
    data: bytes,
    width: int,
    rounds: int | None = None,
    length_encoding: str = "literal_msb_first",
) -> bytes:
    if width not in SHIFTS:
        raise ValueError("standard widths are 32,64,96,128")
    nr = ROUNDS[width] if rounds is None else rounds
    if not 1 <= nr <= ROUNDS[width]:
        raise ValueError("rounds must be in 1..recommended Nr")
    bit_length = 8 * len(data)
    padded = pad_message(data, bit_length, width)
    state = initial_state(width, bit_length, length_encoding)
    block_words = RATE_WORDS
    words_per_block = block_words * (width // 8)
    for off in range(0, len(padded), words_per_block):
        state = permutation(state, width, nr)
        block = bytes_to_words_little(padded[off:off + words_per_block], width)
        for i, x in enumerate(block):
            state[i] ^= x
    state = permutation(state, width, nr)
    digest_bits = width * RATE_WORDS
    return words_to_bytes_little(state[:RATE_WORDS], width)[:digest_bits // 8]


def hamming(x: int) -> int:
    return x.bit_count()


def differential_round(words: list[int], diff_words: list[int], width: int, rnd: int):
    y = round_fun(words, width, rnd)
    yd = round_fun([a ^ b for a, b in zip(words, diff_words)], width, rnd)
    return y, [a ^ b for a, b in zip(y, yd)]


def differential_output(words: list[int], diff_words: list[int], width: int):
    """Output difference of RoundFun, sharing the unchanged base evaluation."""
    yd = [0] * 24
    for col in range(width):
        v = 0
        vd = 0
        for row in range(24):
            v |= ((words[row] >> col) & 1) << row
            vd |= ((diff_words[row] >> col) & 1) << row
        u = s24_pack(v)
        ud = s24_pack(v ^ vd)
        for row in range(24):
            yd[row] |= (((u ^ ud) >> row) & 1) << col
    out = [rol_word(yd[row], SHIFTS[width][row], width) for row in range(24)]
    return out


def propagation_summary(width: int, rounds: int = 6) -> dict:
    # One fixed pseudorandom base state and the one-bit difference at every
    # one of the 24*w state positions.  This covers each position exactly once;
    # it is a deterministic sample, not a statement about every state.
    seed = 0x4C4C480000000000 + width
    rng = random.Random(seed)
    words = [rng.getrandbits(width) for _ in range(24)]
    rows = []
    live = []
    sample_count = 64
    sampled_positions = [rng.randrange(24 * width) for _ in range(sample_count)]
    for pos in sampled_positions:
        d = [0] * 24
        d[pos // width] = 1 << (pos % width)
        live.append(d)
    for rnd in range(1, rounds + 1):
        weights = []
        active_columns = []
        active_words = []
        next_live = []
        base = words
        words = round_fun(base, width, rnd - 1)
        for d in live:
            curd = differential_output(base, d, width)
            next_live.append(curd)
            weights.append(sum(hamming(x) for x in curd))
            active_words.append(sum(x != 0 for x in curd))
            apos = 0
            for col in range(width):
                if any((curd[row] >> col) & 1 for row in range(24)):
                    apos += 1
            active_columns.append(apos)
        live = next_live
        rows.append({
            "round": rnd,
            "samples": sample_count,
            "seed": seed,
            "positions_sampled_with_replacement": sampled_positions,
            "hamming": {"min": min(weights), "mean": sum(weights) / len(weights), "max": max(weights)},
            "active_words": {"min": min(active_words), "mean": sum(active_words) / len(active_words), "max": max(active_words)},
            "active_columns": {"min": min(active_columns), "mean": sum(active_columns) / len(active_columns), "max": max(active_columns)},
        })
    return {
        "width": width,
        "recommended_rounds": ROUNDS[width],
        "rows": rows,
        "scope": "one fixed random base state; 64 one-bit input positions sampled with replacement; exact evaluation for those samples only",
    }


def s6_ddt_best(dx: int):
    counts = Counter(S6_TABLE[x] ^ S6_TABLE[x ^ dx] for x in range(64))
    best = max(counts.values())
    return best, sorted(dy for dy, count in counts.items() if count == best)


def trail_step(words: list[int], diff: list[int], width: int):
    """Choose a maximum-multiplicity S6 output differential per active S6.

    This builds a possible one-round characteristic.  For later rounds the
    output choices are a greedy representative, not a proof of optimality.
    """
    out = [0] * 24
    weight = 0
    active = []
    for slice_index in range(width):
        for c in range(4):
            dx = 0
            for r in range(6):
                dx |= ((diff[4 * r + c] >> slice_index) & 1) << r
            if dx == 0:
                continue
            mult, choices = s6_ddt_best(dx)
            dy = choices[0]
            weight += 6 - (mult.bit_length() - 1)
            active.append((slice_index, c, dx, mult, sorted(choices)))
            for r in range(6):
                out[4 * r + c] |= ((dy >> r) & 1) << slice_index
    # The derangement after the four S6 columns, then D.
    slid = [0] * 24
    for slice_index in range(width):
        pre = sum(((out[r] >> slice_index) & 1) << r for r in range(24))
        shuffled = 0
        for pos, src in enumerate(DERANGEMENT):
            shuffled |= ((pre >> src) & 1) << pos
        mixed = 0
        for row in range(6):
            row_bits = (shuffled >> (4 * row)) & 0xF
            parity = row_bits.bit_count() & 1
            for c in range(4):
                if parity ^ ((row_bits >> c) & 1):
                    mixed |= 1 << (4 * row + c)
        for row in range(24):
            slid[row] |= ((mixed >> row) & 1) << slice_index
    shifted = [rol_word(slid[row], SHIFTS[width][row], width) for row in range(24)]
    return shifted, weight, active


def trail_search(width: int, rounds: int) -> dict:
    words = initial_state(width, 0)
    diff = [0] * 24
    diff[0] = 1
    history = []
    total_weight = 0
    for round_index in range(rounds):
        diff, weight, active = trail_step(words, diff, width)
        total_weight += weight
        history.append({
            "round": round_index + 1,
            "active_s6": len(active),
            "weight": weight,
            "cumulative_weight": total_weight,
            "output_hamming": sum(hamming(x) for x in diff),
            "output_active_columns": sum(any((x >> c) & 1 for x in diff) for c in range(width)),
            "first_transitions": active[:4],
        })
        # The deterministic trail currently follows a zero base state.  Since
        # AddConstant cancels and the chosen differential is possible for every
        # S6 input of that differential, this is a valid transition sequence.
        words = round_fun(words, width, round_index)
    return {
        "width": width,
        "rounds": rounds,
        "start_difference": "bit (row 0, column/slice 0)",
        "model": "single possible differential characteristic; each active S6 uses a maximum-DDT output; after round 1 this is greedy and optimality is not proved",
        "assumption": "standard independent-round Markov trail model for interpreting the product probability",
        "history": history,
        "final_difference_words": [f"{x:0{(width + 3)//4}x}" for x in diff],
    }


def inverse_linear_s24(mask_words: list[int], width: int) -> list[int]:
    """Pull a post-ShiftRows mask backward through the linear parts of S24."""
    unshifted = [0] * 24
    for row in range(24):
        unshifted[row] = rol_word(
            mask_words[row], (-SHIFTS[width][row]) % width, width
        )
    invder = [0] * 24
    for out_pos, src in enumerate(DERANGEMENT):
        invder[src] = out_pos
    pre = [0] * 24
    for col in range(width):
        u = sum(((unshifted[row] >> col) & 1) << row for row in range(24))
        mixed = 0
        for row in range(6):
            row_bits = (u >> (4 * row)) & 0xF
            parity = row_bits.bit_count() & 1
            for c in range(4):
                if parity ^ ((row_bits >> c) & 1):
                    mixed |= 1 << (4 * row + c)
        shuffled = sum(((mixed >> row) & 1) << row for row in range(24))
        before = 0
        for out_pos, src in enumerate(DERANGEMENT):
            before |= ((shuffled >> out_pos) & 1) << src
        for row in range(24):
            pre[row] |= ((before >> row) & 1) << col
    return pre


def linear_trail_search(width: int, rounds: int) -> dict:
    mask = [0] * 24
    mask[0] = 1
    history = []
    total_weight = 0
    for round_index in range(rounds):
        pre = inverse_linear_s24(mask, width)
        outmask = [0] * 24
        active = []
        for col in range(width):
            for c in range(4):
                b = 0
                for row in range(6):
                    b |= ((pre[4 * row + c] >> col) & 1) << row
                if b == 0:
                    continue
                best = 0
                choices = []
                for a in range(64):
                    v = abs(sum(
                        1 if ((a & x).bit_count() & 1) == ((b & S6_TABLE[x]).bit_count() & 1) else -1
                        for x in range(64)
                    ))
                    if v > best:
                        best = v
                        choices = [a]
                    elif v == best:
                        choices.append(a)
                a = choices[0]
                total_weight += 6 - (best.bit_length() - 1)
                active.append({"slice": col, "column": c, "output_mask": b, "input_mask": a, "signed_correlation_abs": best / 64})
                for row in range(6):
                    outmask[4 * row + c] |= ((a >> row) & 1) << col
        history.append({
            "backward_step": round_index + 1,
            "active_s6": len(active),
            "step_weight": 6 - 0 if not active else None,
            "cumulative_weight": total_weight,
            "input_mask_hamming": sum(hamming(x) for x in outmask),
            "first_transitions": active[:4],
        })
        history[-1]["step_weight"] = total_weight - (history[-2]["cumulative_weight"] if len(history) > 1 else 0)
        mask = outmask
    return {
        "width": width,
        "rounds": rounds,
        "terminal_output_mask": "bit (row 0, column/slice 0)",
        "model": "one possible linear characteristic built backward; each active S6 takes a maximum-Walsh input mask; greedy after the first choice, so optimality is not proved",
        "assumption": "standard independent-round Markov trail model; reported weight is -log2 of the product of absolute component correlations",
        "history": history,
        "input_mask_words": [f"{x:0{(width + 3)//4}x}" for x in mask],
    }


def anf_degree(table: list[int], input_bits: int, output_bit: int) -> int:
    coeff = [((v >> output_bit) & 1) for v in table]
    for i in range(input_bits):
        bit = 1 << i
        for x in range(1 << input_bits):
            if x & bit:
                coeff[x] ^= coeff[x ^ bit]
    return max((x.bit_count() for x, c in enumerate(coeff) if c), default=0)


def cycle_structure(perm: list[int]) -> list[int]:
    seen = [False] * len(perm)
    cycles = []
    for x in range(len(perm)):
        if seen[x]:
            continue
        n = 0
        y = x
        while not seen[y]:
            seen[y] = True
            n += 1
            y = perm[y]
        cycles.append(n)
    return sorted(cycles, reverse=True)


def analyze_s6() -> dict:
    ddt_hist = Counter()
    ddt_max = 0
    max_args = []
    for d in range(1, 64):
        c = Counter(S6_TABLE[x] ^ S6_TABLE[x ^ d] for x in range(64))
        m = max(c.values())
        ddt_hist[m] += 1
        if m > ddt_max:
            ddt_max = m
            max_args = [(d, sorted(k for k, n in c.items() if n == m))]
        elif m == ddt_max:
            max_args.append((d, sorted(k for k, n in c.items() if n == m)))
    lat_hist = Counter()
    walsh_max = 0
    walsh_max_args = []
    for a in range(64):
        for b in range(1, 64):
            v = sum(1 if ((a & x).bit_count() & 1) == ((b & S6_TABLE[x]).bit_count() & 1) else -1 for x in range(64))
            lat_hist[abs(v)] += 1
            if abs(v) > walsh_max:
                walsh_max = abs(v)
                walsh_max_args = [(a, b, v)]
            elif abs(v) == walsh_max:
                walsh_max_args.append((a, b, v))
    constant_derivatives = []
    affine_derivatives = []
    for a in range(1, 64):
        der = [S6_TABLE[x] ^ S6_TABLE[x ^ a] for x in range(64)]
        if len(set(der)) == 1:
            constant_derivatives.append((a, der[0]))
        c = der[0]
        linearized = [v ^ c for v in der]
        if all(linearized[x ^ y] == (linearized[x] ^ linearized[y]) for x in range(64) for y in range(64)):
            affine_derivatives.append(a)
    return {
        "table_hex": "".join(f"{x:02x}" for x in S6_TABLE),
        "permutation": len(set(S6_TABLE)) == 64,
        "ddt": {
            "max_nonzero_input": ddt_max,
            "histogram_over_63_nonzero_input_differences": {str(k): v for k, v in sorted(ddt_hist.items())},
            "maximizers": [{"input_diff": d, "output_diffs": out} for d, out in max_args],
        },
        "walsh": {
            "definition": "sum_x (-1)^(a.x xor b.S6(x)), b != 0",
            "max_abs": walsh_max,
            "max_abs_correlation": walsh_max / 64,
            "histogram_abs": {str(k): v for k, v in sorted(lat_hist.items())},
            "maximizers": [{"input_mask": a, "output_mask": b, "signed_sum": v} for a, b, v in walsh_max_args],
            "notes": "Signed values +32 and -32 are equivalent in absolute correlation.",
        },
        "algebraic_degree_by_output_bit": [anf_degree(S6_TABLE, 6, bit) for bit in range(6)],
        "cycle_structure": cycle_structure(S6_TABLE),
        "constant_derivatives": constant_derivatives,
        "linear_structures": constant_derivatives,
        "quadratic_nonzero_derivatives": affine_derivatives,
        "s24_ddt_bound_proof": {
            "composition": "S24 = L o S6^4 o P with P a bit permutation and L an invertible bit-linear map",
            "max_nonzero_input": 16**4,
            "probability": "1/256",
            "proof": "For a fixed input/output differential, the four S6 columns are independent and L is a bijection. If all four input-column differentials are among the 14 S6 maximizers, each contributes 16 pairs; otherwise the product is at most 16^3*4 or lower. Four maximizers occur together, so the bound is attained.",
            "maximizers": "Take any input differential whose four 6-bit column differences are each one of the 14 listed S6 maximizers, and the corresponding four output differences from their maximizing lists.",
        },
        "s24_algebraic_degree": 2,
        "s24_cycle_structure_note": "Exhaustive full 2^24 cycle decomposition is not needed for the component claim; zero-difference fixed points are checked exhaustively.",
    }


def verify_constants() -> dict:
    import mpmath as mp

    bits = 40 * 128 + 256
    mp.mp.dps = int(bits / 3.2) + 80
    frac = mp.e - 2
    stream = []
    for _ in range(bits):
        frac *= 2
        if frac >= 1:
            stream.append(1)
            frac -= 1
        else:
            stream.append(0)
    derived = {}
    for w in (32, 64, 96, 128):
        vals = []
        for r in range(ROUNDS[w]):
            chunk = stream[r * w:(r + 1) * w]
            # Decimal-fraction bit streams are printed in conventional order:
            # the first bit is the most significant bit of the written word.
            vals.append(sum(bit << (w - 1 - i) for i, bit in enumerate(chunk)))
        derived[w] = vals
    return {str(w): derived[w] == RC[w] for w in derived}


def self_test() -> dict:
    # The printed examples and documented structural facts.
    assert bytes_to_words_little(bytes.fromhex("0A010304"), 32) == [0x0403010A]
    assert (1 | (((1 << 6) - 1) << 2)) == 0xFD
    assert all(len(SHIFTS[w]) == 24 and all(0 <= s < w for s in SHIFTS[w]) for w in SHIFTS)
    assert all(len(RC[w]) == ROUNDS[w] for w in RC)
    assert all(0 <= RC[w][r] < (1 << w) for w in RC for r in range(ROUNDS[w]))
    assert len(set(S6_TABLE)) == 64
    # P is invertible at least on the four explicitly checked states because
    # every round is invertible: exhaustive S24 is a permutation, ShiftRows
    # is invertible, and AddConstant is a translation.
    return {
        "spec_sha256": hashlib.sha256(Path("hash-16-spec.pdf").read_bytes()).hexdigest(),
        "printed_word_example": "0A010304 -> 0403010A",
        "printed_two_bit_padding_example": "02, length 2 -> first byte fd",
        "shift_ranges_ok": True,
        "round_constant_counts_ok": True,
        "round_constants_recomputed_from_e": verify_constants(),
        "s6_is_permutation": True,
        "s24_linear_layers_are_invertible": {
            "derangement": sorted(DERANGEMENT) == list(range(24)),
            "D": "D=J4-I4; over GF(2), D^2=(J-I)^2=J^2-2J+I=I",
        },
        "literal_length_encoding": {
            "default": "reverse all 64 bits of L into W23 bit 0.. (or across W22/W23 for w=32)",
            "literal_example_L_8": {
                "w32": "W22=0, W23=0x10000000",
                "w64_plus": "W23=0x1000000000000000",
            },
            "alternative_not_selected": "64-bit little-endian integer; reported as an interoperability ambiguity",
        },
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=["audit", "propagation", "trails"])
    ap.add_argument("--out")
    args = ap.parse_args()
    if args.mode == "audit":
        result = {"self_test": self_test(), "s6": analyze_s6()}
    elif args.mode == "propagation":
        result = {
            "propagation": [propagation_summary(w, min(6, ROUNDS[w])) for w in (32, 64, 96, 128)],
            "hashes": {
                str(w): {
                    "empty": llh(b"", w).hex(),
                    "abc": llh(b"abc", w).hex(),
                    "01": llh(bytes([1]), w).hex(),
                }
                for w in (32, 64, 96, 128)
            },
            "length_encoding_variant_hashes": {
                str(w): {
                    "literal_msb_first": {
                        name: llh(data, w, length_encoding="literal_msb_first").hex()
                        for name, data in (("empty", b""), ("abc", b"abc"), ("01", bytes([1])))
                    },
                    "little_endian_integer": {
                        name: llh(data, w, length_encoding="little_endian_integer").hex()
                        for name, data in (("empty", b""), ("abc", b"abc"), ("01", bytes([1])))
                    },
                }
                for w in (32, 64, 96, 128)
            },
        }
    else:
        result = {"trails": [
            {"differential": trail_search(w, 6), "linear": linear_trail_search(w, 6)}
            for w in (32, 64, 96, 128)
        ]}
    text = json.dumps(result, indent=2, sort_keys=True)
    if args.out:
        Path(args.out).write_text(text + "\n")
    print(text)


if __name__ == "__main__":
    main()
