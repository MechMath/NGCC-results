#!/usr/bin/env python3
"""Literal AXIS specification probe used only to compare textual readings."""

from __future__ import annotations

from dataclasses import dataclass


CONSTANTS_HEX = [
    "243F6A8885A308D3B7E151628AED2A6A9E3779B97F4A7C15",
    "7160C6B758B90A76D81F8650363C93F849CA76E19F938DA4",
    "70FF7724ACB762F7B54CBDE35B659CC7CD71C257B752EEB5",
    "4FD6E6B4FBAB7ECD3120355B0549D6B947EA14CFA7D43857",
    "6B634EF404919AAA03F92D7B7FAEEF105DCD2735332E4029",
    "53C1A2C96C4DE7E3CD0814056FA6E00BD57AC41E845348D4",
    "F3FF90522F99DAE5352FF6633C6EFBA6ABDBF53A09476735",
    "B1A270D3653FB5B8D94570230179F8120D875B906F276D2C",
]
INIT_BITS = [
    [(int(h, 16) >> i) & 1 for i in range(192)] for h in CONSTANTS_HEX
]
EXL = [0, 12, 32, 96, 107, 125, 11]
UPL = [66, 75, 90, 162, 178, 188]


def sbox_bits(bits: list[int]) -> int:
    x5, x4, x3, x2, x1, x0 = bits
    return (x5 & x4) ^ (x3 & x2) ^ (x1 & x0)


def up_res(state: list[list[int]], j: int, m: int, rotate=True) -> None:
    s = state
    cur = s[j]
    tau = sbox_bits(
        [
            s[(j + 5) % 8][EXL[3]],
            s[(j + 5) % 8][EXL[2]],
            s[(j + 3) % 8][EXL[5]],
            s[(j + 3) % 8][EXL[1]],
            s[(j + 1) % 8][EXL[4]],
            s[(j + 1) % 8][EXL[0]],
        ]
    )
    own = sbox_bits([cur[i] for i in [EXL[5], EXL[2], EXL[4], EXL[1], EXL[3], EXL[0]]])
    b = m ^ own ^ tau ^ s[(j - 1) % 8][EXL[6]]
    t0 = cur[EXL[2]] ^ cur[EXL[1]] ^ cur[EXL[0]] ^ b
    t1 = cur[EXL[5]] ^ cur[EXL[4]] ^ cur[EXL[3]] ^ b
    for i in (UPL[2], UPL[1], UPL[0]):
        cur[i] ^= t1
    for i in (UPL[5], UPL[4], UPL[3]):
        cur[i] ^= t0
    if rotate:
        s[j] = cur[1:] + cur[:1]


def up_full(state: list[list[int]], mu: int, nu: int, order: str = "asc") -> None:
    seq = range(8) if order == "asc" else range(7, -1, -1)
    for j in seq:
        up_res(state, j, mu if j % 2 == 0 else nu)


def gen_digest(state: list[list[int]]) -> tuple[int, int]:
    i = EXL[0]
    mu = state[6][i] ^ state[4][i] ^ (state[2][i] & state[0][i])
    nu = state[7][i] ^ state[5][i] ^ (state[3][i] & state[1][i])
    return mu, nu


def pad_bits(bits: list[int], endian: str = "big") -> list[int]:
    length = len(bits)
    s = (-length - 3) % 64
    length_bits = (
        [(length >> (63 - i)) & 1 for i in range(64)]
        if endian == "big"
        else [(length >> i) & 1 for i in range(64)]
    )
    return bits + [1] + [0] * (s + 1) + [1] + length_bits


def stream_bits(total_beats: int) -> list[int]:
    need = 8 * total_beats
    stream = []
    while len(stream) < need:
        for reg in INIT_BITS:
            stream.extend(reg)
    return stream[:need]


@dataclass(frozen=True)
class Options:
    update_order: str = "asc"
    constant_mapping: str = "low_to_high_as_c0"
    constant_phase: str = "continue"
    padding_endian: str = "big"
    digest_order: str = "spec"
    axis768_remainder_source: str = "padded"


def hash_bits(message: list[int], variant: int, opts: Options = Options()) -> list[int]:
    n_fin = 1024
    n_dig = {512: 256, 768: 512, 1024: 1024}[variant]
    padded = pad_bits(message, opts.padding_endian)
    state = [r[:] for r in INIT_BITS]

    remainder_source = padded if opts.axis768_remainder_source == "padded" else message
    if variant == 512:
        n_beats = len(padded) // 2
    elif variant == 1024:
        n_beats = len(padded)
    else:
        rem_len = len(remainder_source)
        rem = rem_len % 192
        if rem == 0:
            n_beats = 2 * len(padded) // 3
        elif rem == 64:
            n_beats = (2 * len(padded) + 64) // 3
        elif rem == 128:
            n_beats = (2 * len(padded) + 32) // 3
        else:
            raise ValueError(f"unsupported AXIS-768 padded remainder {rem}")

    i = 0
    for t in range(n_beats):
        if variant == 512:
            mu, nu = padded[i + 1], padded[i]
            i += 2
        elif variant == 1024:
            mu = nu = padded[i]
            i += 1
        else:
            # The final one-bit tail depends on the padded length remainder.
            rem = len(padded) % 192
            in_tail = (
                (rem == 64 and t >= n_beats - 64)
                or (rem == 128 and t >= n_beats - 32)
            )
            if t % 2 == 0 or in_tail:
                mu = nu = padded[i]
                i += 1
            else:
                mu, nu = padded[i + 1], padded[i]
                i += 2
        up_full(state, mu, nu, opts.update_order)
    if i != len(padded):
        raise AssertionError((variant, i, len(padded), n_beats))

    const_stream = stream_bits(n_fin + n_dig)
    pos = 0

    def refresh() -> None:
        nonlocal pos
        chunk = const_stream[pos : pos + 8]
        pos += 8
        if opts.constant_mapping == "low_to_high_as_c0":
            cs = chunk
        elif opts.constant_mapping == "low_to_high_reversed":
            cs = list(reversed(chunk))
        else:
            raise ValueError(opts.constant_mapping)
        for j in range(8):
            up_res(state, j, cs[j])

    for _ in range(n_fin):
        refresh()
    if opts.constant_phase == "restart":
        pos = 0
    elif opts.constant_phase != "continue":
        raise ValueError(opts.constant_phase)

    pieces = []
    for t in range(n_dig):
        mu, nu = gen_digest(state)
        if variant == 512 or (variant == 768 and t % 2 == 1):
            pieces.extend([mu, nu])
        else:
            pieces.append(mu)
        refresh()

    if opts.digest_order == "spec":
        return list(reversed(pieces))
    if opts.digest_order == "chronological":
        return pieces
    raise ValueError(opts.digest_order)


def bits_to_hex(bits: list[int], byte_order: str = "msb_first") -> str:
    out = []
    for i in range(0, len(bits), 8):
        chunk = bits[i : i + 8]
        if byte_order == "msb_first":
            value = 0
            for bit in chunk:
                value = (value << 1) | bit
        elif byte_order == "lsb_first":
            value = sum(bit << k for k, bit in enumerate(chunk))
        else:
            raise ValueError(byte_order)
        out.append(f"{value:02x}")
    return "".join(out)


def ascii_bits(text: str) -> list[int]:
    bits = []
    for value in text.encode("ascii"):
        bits.extend((value >> (7 - i)) & 1 for i in range(8))
    return bits


if __name__ == "__main__":
    for variant in (512, 768, 1024):
        base = hash_bits(ascii_bits(""), variant)
        print(variant, "empty", bits_to_hex(base))
