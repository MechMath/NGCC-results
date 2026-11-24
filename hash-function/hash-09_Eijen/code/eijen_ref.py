#!/usr/bin/env python3
"""Literal word-level reference model of Eijen from hash-09-spec.pdf.

The specification's displayed state vector is interpreted in increasing word index:
word 4*j+i is A[i][j], and all words are little-endian 64-bit integers.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

MASK64 = (1 << 64) - 1

P0 = (36, 54, 45, 44, 18, 9)
P1 = (56, 46, 54, 34, 19, 51)

SIGMA = (
    22, 0, 29, 19, 26, 4, 1, 23,
    30, 8, 5, 27, 2, 12, 9, 31,
    6, 16, 13, 3, 10, 20, 17, 7,
    14, 24, 21, 11, 18, 28, 25, 15,
)

ROUND_CONSTANTS = (
    (0x243F6A8885A308D3, 0x13198A2E03707344),
    (0xA4093822299F31D0, 0x082EFA98EC4E6C89),
    (0x452821E638D01377, 0xBE5466CF34E90C6C),
    (0xC0AC29B7C97C50DD, 0x3F84D5B5B5470917),
    (0x9216D5D98979FB1B, 0xD1310BA698DFB5AC),
    (0x2FFD72DBD01ADFB7, 0xB8E1AFED6A267E96),
    (0xBA7C9045F12C7F99, 0x24A19947B3916CF7),
    (0x0801F2E2858EFC16, 0x636920D871574E69),
    (0xA458FEA3F4933D7E, 0x0D95748F728EB658),
    (0x718BCD5882154AEE, 0x7B54A41DC25A59B5),
    (0x9C30D5392AF26013, 0xC5D1B023286085F0),
    (0xCA417918B8DB38EF, 0x8E79DCB0603A180E),
    (0x6C9E0E8BB01E8A3E, 0xD71577C1BD314B27),
    (0x78AF2FDA55605C60, 0xE65525F3AA55AB94),
    (0x5748986263E81440, 0x55CA396A2AAB10B6),
    (0xB4CC5C341141E8CE, 0xA15486AF7C72E993),
)

PROFILES = {
    256: (1728, 320),
    384: (1600, 448),
    512: (1472, 576),
    768: (1216, 832),
    1024: (960, 1088),
}


def rotl64(x: int, n: int) -> int:
    assert 0 <= n < 64
    return ((x << n) | (x >> (64 - n))) & MASK64 if n else x


def mixquad(words: list[int], pi: tuple[int, ...], constant: int) -> None:
    """In-place literal MixQuad update of a four-word column."""
    a, b, c, d = words
    p0, p1, p2, p3, p4, p5 = pi

    a = (a + b) & MASK64
    d ^= a
    d = rotl64(d, p0)
    a = rotl64(a, p4) ^ constant
    c = (c + d) & MASK64
    b ^= c
    b = rotl64(b, p1)
    c = rotl64(c, p5)

    a = (a + b) & MASK64
    d ^= a
    d = rotl64(d, p2)
    c = (c + d) & MASK64
    b ^= c
    b = rotl64(b, p3)
    words[:] = [a, b, c, d]


def posperm(state: list[int], sigma: tuple[int, ...] = SIGMA) -> list[int]:
    assert len(state) == len(sigma) == 32
    return [state[sigma[i]] for i in range(32)]


def amix4(state: list[int]) -> list[int]:
    out = [0] * 32
    for j in range(8):
        a, b, c, d = state[4 * j:4 * j + 4]
        out[4 * j:4 * j + 4] = [b ^ c ^ d, a ^ c ^ d, a ^ b ^ d, a ^ b ^ c]
    return out


def permutation_round(
    state: list[int],
    round_index: int,
    *,
    inverse_posperm: bool = False,
) -> list[int]:
    assert 0 <= round_index < 16
    z = list(state)
    for j in range(8):
        pi = P0 if j < 4 else P1
        constant = ROUND_CONSTANTS[round_index][0 if j < 4 else 1]
        column = z[4 * j:4 * j + 4]
        mixquad(column, pi, constant)
        z[4 * j:4 * j + 4] = column
    if inverse_posperm:
        u = [0] * 32
        for l, source in enumerate(SIGMA):
            u[source] = z[l]
    else:
        u = posperm(z)
    w = amix4(u)
    return posperm(w, tuple(reversed(SIGMA)) if inverse_posperm else SIGMA)


def permutation(
    state: Iterable[int],
    rounds: int = 16,
    *,
    inverse_posperm: bool = False,
) -> list[int]:
    x = list(state)
    if len(x) != 32:
        raise ValueError("permutation state must contain exactly 32 words")
    for r in range(rounds):
        x = permutation_round(x, r, inverse_posperm=inverse_posperm)
    return x


def bytes_to_words_little(data: bytes, words: int = 32) -> list[int]:
    if len(data) > 8 * words:
        raise ValueError("input does not fit the requested word array")
    padded = data + b"\x00" * (8 * words - len(data))
    return [int.from_bytes(padded[8 * i:8 * i + 8], "little") for i in range(words)]


def words_to_bytes_little(words: Iterable[int]) -> bytes:
    return b"".join(int(w).to_bytes(8, "little") for w in words)


def pad_message(message: bytes, rate: int) -> bytes:
    if rate % 8:
        raise ValueError("this byte-oriented model requires a byte-aligned rate")
    rate_bytes = rate // 8
    return message + b"\x01" + b"\x00" * ((-len(message) - 1) % rate_bytes)


def hash_message(
    message: bytes,
    h: int,
    *,
    trace: bool = False,
    inverse_posperm: bool = False,
    capacity_feedforward: bool = True,
    omit_final_capacity_feedforward: bool = False,
    feedforward_before_final_constant: bool = False,
) -> tuple[bytes, list[list[int]]]:
    """Return digest bytes and, if requested, the state trace.

    The returned digest is the rightmost h bits serialized little-endian within
    each displayed 64-bit word, in increasing word-index order.
    """
    if h not in PROFILES:
        raise ValueError(f"unsupported digest size {h}")
    rate, capacity = PROFILES[h]
    padded = pad_message(message, rate)
    block_words = rate // 64
    state = [0] * 32
    trace = [list(state)] if trace else []

    blocks = len(padded) // (rate // 8)
    for block_number in range(blocks):
        block_bytes = padded[block_number * rate // 8:(block_number + 1) * rate // 8]
        block = bytes_to_words_little(block_bytes, block_words)
        s = list(state)
        for j, word in enumerate(block):
            s[j] ^= word
        feedforward_state = list(s)
        if block_number == blocks - 1:
            # 1_c = 0^(c-1) || 1. In the capacity's final little-endian word,
            # this is the most-significant bit.
            s[31] ^= 1 << 63
        permuted = permutation(s, inverse_posperm=inverse_posperm)
        use_cf = capacity_feedforward and not (
            omit_final_capacity_feedforward and block_number == blocks - 1
        )
        cf_state = feedforward_state if feedforward_before_final_constant else s
        state = [
            permuted[j] ^ cf_state[j]
            if use_cf and j >= block_words
            else permuted[j]
            for j in range(32)
        ]
        if trace:
            trace.append(list(state))

    digest_words = state[32 - h // 64:32]
    return words_to_bytes_little(digest_words), trace


def digest_hex(digest: bytes) -> str:
    return " ".join(digest[i:i + 8].hex().upper() for i in range(0, len(digest), 8))


EXPECTED = {
    256: {
        b"\x00" * 248: "80228A17A23CBEAB 2887F1A68F207F64 CF37AFDE64829FB7 B51A409CE71378A7",
        b"\xff" * 248: "7E3B2A5EE4CF56D3 FF4646C9A3577E97 059933A754462ECA CDE04218D1AE0004",
        b"abc": "C832C8FBDAB9CBB6 0824D2E879ACE7CE B1F902E54FCAA9DC 81E09F3C71B04F86",
    },
    384: {
        b"\x00" * 256: "B073FF1383DED03B 501800B493D0A9D9 80228A17A23CBEAB 2887F1A68F207F64 CF37AFDE64829FB7 B51A409CE71378A7",
        b"\xff" * 256: "AAB7CF11B814EB94 3A3702838F26095D A09ADCDBBBE52337 24CCEE1FA4DC4B4D A6A3EA682BF08970 BF19275E9FABBEFD",
        b"abc": "A03123E2B9D22A23 02B49E012D880194 C832C8FBDAB9CBB6 0824D2E879ACE7CE B1F902E54FCAA9DC 81E09F3C71B04F86",
    },
    512: {
        b"\x00" * 248: "20720A80BCA29353 9A5310A46EFA2926 B073FF1383DED03B 501800B493D0A9D9 80228A17A23CBEAB 2887F1A68F207F64 CF37AFDE64829FB7 B51A409CE71378A7",
        b"\xff" * 248: "3B175FF348C41499 955B22A6E54982D8 08847F0E2FE7C269 B51E1DCA1C1FF9C8 25897C9F871AFFE4 11E0B646553C2F16 C2E5DD95F186CA01 3D4F2019FBAA0174",
        b"abc": "B0F1FC89DFF89974 05CEAE73C34D9A97 A03123E2B9D22A23 02B49E012D880194 C832C8FBDAB9CBB6 0824D2E879ACE7CE B1F902E54FCAA9DC 81E09F3C71B04F86",
    },
    1024: {
        b"\x00" * 248: "B3F4CB5B73AB79B2 0EDC62546C428718 A1049A487EF76599 FC96E7B6494278A9 C3DD02B9FE08D75E 316A87479AE6A8F4 7CB4F076F3ED6B07 849B986B2CF1689B 20720A80BCA29353 9A5310A46EFA2926 B073FF1383DED03B 501800B493D0A9D9 80228A17A23CBEAB 2887F1A68F207F64 CF37AFDE64829FB7 B51A409CE71378A7",
        b"\xff" * 248: "10CA8AA88377EB4A 7487213EE0384BBA 5CBB5A9300C000CE 9192DE12D5D81E85 535A50AAD23556E4 F795F11F73702C7B FF42DB838BE183B1 B1A31D9C96B025BD 47B0CD040C6B45CC BC54F8D7B3BEB6CE 4C4D2BBDACB1D7EF 7918BD2E0912F86E 895BFDE5EB24DCFA 1EE5124527E17473 B73B1C6FFE41F781 0CF8C022BA818EEA",
        b"abc": "738521FE5D9A3EB4 A08418A650071F29 D832089843253040 64AAE1A2402E5B30 FC9E471C3278C941 6638EE7D845FF6F1 CE5EF11EABAAB83B 444CB95EAC455791 B0F1FC89DFF89974 05CEAE73C34D9A97 A03123E2B9D22A23 02B49E012D880194 C832C8FBDAB9CBB6 0824D2E879ACE7CE B1F902E54FCAA9DC 81E09F3C71B04F86",
    },
}


def run_vectors(*, inverse_posperm: bool = False, trace: bool = False) -> dict:
    vectors = []
    for h in (256, 384, 512, 1024):
        for message, expected in EXPECTED[h].items():
            got_bytes, state_trace = hash_message(
                message, h, trace=trace, inverse_posperm=inverse_posperm
            )
            got = digest_hex(got_bytes)
            vectors.append(
                {
                    "profile": h,
                    "message_bytes": len(message),
                    "message_sha256": hashlib.sha256(message).hexdigest(),
                    "expected": expected,
                    "got": got,
                    "match": got == expected,
                    "trace": [
                        " ".join(f"{w:016X}" for w in state) for state in state_trace
                    ] if trace else None,
                }
            )
    return {
        "model": "literal word-index/little-endian interpretation",
        "inverse_posperm": inverse_posperm,
        "rounds": 16,
        "vectors": vectors,
        "all_match": all(v["match"] for v in vectors),
    }


def run_vector_diagnostic() -> dict:
    """Test the capacity-feed-forward omission implicated by the vectors.

    The all-zero/all-one digests identify their own message lengths: they
    equal one complete rate block. The PDF's displayed word counts differ
    from those lengths, so both are reported explicitly.
    """
    cases = []
    for h, (rate, _) in PROFILES.items():
        if h == 768:
            continue
        for fill, source_length in ((0x00, 248 if h in (256, 512, 1024) else 256),
                                    (0xFF, 248 if h in (256, 512, 1024) else 256)):
            expected = EXPECTED[h][bytes([fill]) * source_length]
            message = bytes([fill]) * (rate // 8)
            literal, _ = hash_message(message, h)
            no_cf, _ = hash_message(
                message, h, feedforward_before_final_constant=True
            )
            literal_hex = digest_hex(literal)
            no_cf_hex = digest_hex(no_cf)
            literal_numeric = int.from_bytes(literal, "little")
            expected_numeric = int.from_bytes(bytes.fromhex(expected.replace(" ", "")), "little")
            no_cf_numeric = int.from_bytes(no_cf, "little")
            cases.append(
                {
                    "profile": h,
                    "fill": f"{fill:02X}",
                    "pdf_displayed_message_words": source_length // 8,
                    "message_bytes_used_by_vectors": rate // 8,
                    "literal_matches": literal_hex == expected,
                    "feedforward_before_final_constant_matches": no_cf_hex == expected,
                    "literal_xor_expected": f"{literal_numeric ^ expected_numeric:0{h // 4}X}",
                    "no_cf_xor_expected": f"{no_cf_numeric ^ expected_numeric:0{h // 4}X}",
                    "expected": expected,
                    "literal": literal_hex,
                    "feedforward_before_final_constant": no_cf_hex,
                }
            )
    message = b"abc"
    abc_no_cf = {}
    for h in (256, 384, 512, 1024):
        got, _ = hash_message(message, h, feedforward_before_final_constant=True)
        abc_no_cf[h] = {
            "expected": EXPECTED[h][message],
            "feedforward_before_final_constant": digest_hex(got),
            "match": digest_hex(got) == EXPECTED[h][message],
        }
    return {
        "diagnostic": "published vectors versus feed-forward before final constant",
        "single_rate_block_cases": cases,
        "single_rate_block_all_match": all(
            c["feedforward_before_final_constant_matches"] for c in cases
        ),
        "abc": abc_no_cf,
        "abc_all_match": all(v["match"] for v in abc_no_cf.values()),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--inverse-posperm", action="store_true")
    parser.add_argument("--trace", action="store_true")
    parser.add_argument("--diagnostic", action="store_true")
    parser.add_argument("--output")
    args = parser.parse_args()
    result = (
        run_vector_diagnostic()
        if args.diagnostic
        else run_vectors(inverse_posperm=args.inverse_posperm, trace=args.trace)
    )
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        Path(args.output).write_text(rendered)
    print(rendered, end="")


if __name__ == "__main__":
    main()
