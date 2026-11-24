#!/usr/bin/env python3
"""Independent executable transcription of the QSH paper specification.

This is a working model for diagnosis.  It is not, by itself, run evidence.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

MASK32 = (1 << 32) - 1
MASK64 = (1 << 64) - 1


@dataclass(frozen=True)
class Variant:
    name: str
    width: int
    rounds: int
    block_words: int
    iv_word0: int
    digest_bits: int

    @property
    def words(self) -> int:
        return 64

    @property
    def mask(self) -> int:
        return (1 << self.width) - 1

    @property
    def cv_words(self) -> int:
        return self.block_words

    @property
    def digest_words(self) -> int:
        return (self.digest_bits + self.width - 1) // self.width


QSH512 = Variant("QSH-512", 32, 9, 32, 17, 512)
QSH768 = Variant("QSH-768", 64, 18, 32, 1, 768)
QSH1024 = Variant("QSH-1024", 64, 18, 32, 7, 1024)

CHUNK_START = 1
CHUNK_END = 2
PARENT = 4
ROOT = 8


def _rotl(x: int, n: int, width: int) -> int:
    mask = (1 << width) - 1
    n %= width
    return ((x << n) | (x >> (width - n))) & mask if n else x & mask


def _rotr(x: int, n: int, width: int) -> int:
    return _rotl(x, -n, width)


def g(words: list[int], width: int) -> None:
    """In-place G on four words.

    The paper names the four words (a,b,c,d).  At width 32 its rotations are
    sigma=(1,15,0,8), tau=(16,12,8,7); width 64 scales as specified.
    """
    a, b, c, d = words
    mask = (1 << width) - 1
    sigma = (1, width // 2 - 1, 0, width // 4)
    tau = (width // 2, width // 2 - 4, width // 4, width // 4 - 1)

    a = (a + _rotl(b, sigma[0], width)) & mask
    d = _rotl(d ^ a, tau[0], width)
    c = (c + _rotl(d, sigma[1], width)) & mask
    b = _rotl(b ^ c, tau[1], width)
    a = (a + _rotl(b, sigma[2], width)) & mask
    d = _rotl(d ^ a, tau[2], width)
    c = (c + _rotl(d, sigma[3], width)) & mask
    b = _rotl(b ^ c, tau[3], width)
    words[:] = [a, b, c, d]


def _index(x0: int, x1: int, x2: int) -> int:
    # Paper, Section 3.3: i = 16*x0 + 4*x2 + x1.
    return 16 * x0 + 4 * x2 + x1


def _p16_plane(words: list[int], fixed: int, axis: tuple[int, int]) -> None:
    """Apply P16 to a coordinate plane, in the directions named by Algorithm 1."""
    u, v = axis
    old = words.copy()
    for x_u in range(4):
        for x_v in range(4):
            coords = [0, 0, 0]
            coords[fixed] = fixed_value = (
                (x_u if 0 not in axis else 0)
            )
            # The caller supplies fixed coordinate through a closure-like patch
            # below; this helper is superseded by the explicit d=3 routine.
            del coords, fixed_value
    raise AssertionError("unreachable")


def _p16(plane: list[int]) -> list[int]:
    """Rows are the first coordinate, columns the second."""
    return [plane[4 * i + ((j + i) % 4)] for i in range(4) for j in range(4)]


def _p16_apply(words: list[int], fixed_axis: int, fixed: int, axes: tuple[int, int]) -> None:
    a, b = axes
    plane = []
    coords = [0, 0, 0]
    coords[fixed_axis] = fixed
    for i in range(4):
        for j in range(4):
            coords[a] = i
            coords[b] = j
            plane.append(words[_index(*coords)])
    shuffled = _p16(plane)
    for i in range(4):
        for j in range(4):
            coords[a] = i
            coords[b] = j
            words[_index(*coords)] = shuffled[4 * i + j]


def _invert_p16_apply(words: list[int], fixed_axis: int, fixed: int, axes: tuple[int, int]) -> None:
    a, b = axes
    plane = []
    coords = [0, 0, 0]
    coords[fixed_axis] = fixed
    for i in range(4):
        for j in range(4):
            coords[a] = i
            coords[b] = j
            plane.append(words[_index(*coords)])
    # a'[i,j] = a[i,j+i], so a[i,k] = a'[i,k-i].
    inv = [0] * 16
    for i in range(4):
        for j in range(4):
            inv[4 * i + j] = plane[4 * i + ((j - i) % 4)]
    for i in range(4):
        for j in range(4):
            coords[a] = i
            coords[b] = j
            words[_index(*coords)] = inv[4 * i + j]


def _g_axis(words: list[int], fixed_axes: tuple[int, int], varied_axis: int, width: int) -> None:
    coords_fixed = [0, 0, 0]
    for i in range(4):
        for j in range(4):
            coords_fixed[fixed_axes[0]] = i
            coords_fixed[fixed_axes[1]] = j
            coords = coords_fixed.copy()
            quad = []
            for t in range(4):
                coords[varied_axis] = t
                quad.append(words[_index(*coords)])
            g(quad, width)
            for t in range(4):
                coords[varied_axis] = t
                words[_index(*coords)] = quad[t]


def round_function(words: list[int], width: int, final_column_only: bool = False) -> None:
    # Axis 0 layer.
    _g_axis(words, (1, 2), 0, width)
    if final_column_only:
        return

    # i=1: shuffle each x2 slice in axes (0,1), mix axis 0, undo shuffle.
    for x2 in range(4):
        _p16_apply(words, 2, x2, (0, 1))
    _g_axis(words, (1, 2), 0, width)
    for x2 in range(4):
        _invert_p16_apply(words, 2, x2, (0, 1))

    # i=2: shuffle each x0 slice in axes (1,2), mix axis 1, undo shuffle.
    for x0 in range(4):
        _p16_apply(words, 0, x0, (1, 2))
    _g_axis(words, (0, 2), 1, width)
    for x0 in range(4):
        _invert_p16_apply(words, 0, x0, (1, 2))


def permutation(words: Iterable[int], variant: Variant) -> list[int]:
    out = list(words)
    for _ in range(variant.rounds):
        round_function(out, variant.width)
    round_function(out, variant.width, final_column_only=True)
    return out


def _g_inverse(words: list[int], width: int) -> None:
    a, b, c, d = words
    mask = (1 << width) - 1
    sigma = (1, width // 2 - 1, 0, width // 4)
    tau = (width // 2, width // 2 - 4, width // 4, width // 4 - 1)

    b = _rotr(b, tau[3], width) ^ c
    c = (c - _rotl(d, sigma[3], width)) & mask
    d = _rotr(d, tau[2], width) ^ a
    a = (a - _rotl(b, sigma[2], width)) & mask
    b = _rotr(b, tau[1], width) ^ c
    c = (c - _rotl(d, sigma[1], width)) & mask
    d = _rotr(d, tau[0], width) ^ a
    a = (a - _rotl(b, sigma[0], width)) & mask
    words[:] = [a, b, c, d]


def _g_axis_inverse(words: list[int], fixed_axes: tuple[int, int], varied_axis: int, width: int) -> None:
    coords_fixed = [0, 0, 0]
    for i in range(4):
        for j in range(4):
            coords_fixed[fixed_axes[0]] = i
            coords_fixed[fixed_axes[1]] = j
            coords = coords_fixed.copy()
            quad = []
            for t in range(4):
                coords[varied_axis] = t
                quad.append(words[_index(*coords)])
            _g_inverse(quad, width)
            for t in range(4):
                coords[varied_axis] = t
                words[_index(*coords)] = quad[t]


def round_function_inverse(words: list[int], width: int, final_column_only: bool = False) -> None:
    if not final_column_only:
        for x0 in range(4):
            _p16_apply(words, 0, x0, (1, 2))
        _g_axis_inverse(words, (0, 2), 1, width)
        for x0 in range(4):
            _invert_p16_apply(words, 0, x0, (1, 2))
        for x2 in range(4):
            _p16_apply(words, 2, x2, (0, 1))
        _g_axis_inverse(words, (1, 2), 0, width)
        for x2 in range(4):
            _invert_p16_apply(words, 2, x2, (0, 1))
    _g_axis_inverse(words, (1, 2), 0, width)


def permutation_inverse(words: Iterable[int], variant: Variant) -> list[int]:
    out = list(words)
    round_function_inverse(out, variant.width, final_column_only=True)
    for _ in range(variant.rounds):
        round_function_inverse(out, variant.width)
    return out


def compression(message: list[int], state: list[int], variant: Variant, flag: int, *, flag_last: bool = False) -> list[int]:
    if len(message) != variant.block_words or len(state) != variant.words:
        raise ValueError("wrong vector length")
    mask = variant.mask
    pre = state.copy()
    for j, m in enumerate(message):
        pre[variant.block_words + j] = (pre[variant.block_words + j] + m) & mask
    flag_word = variant.words - 1 if flag_last else 0
    pre[flag_word] ^= flag
    post = permutation(pre, variant)
    out = post.copy()
    for j, m in enumerate(message):
        out[j] = (out[j] + m) & mask
    return out


def compression_inverse(output: list[int], message: list[int], variant: Variant, flag: int, *, flag_last: bool = False) -> list[int]:
    """Invert F for fixed M and flag.

    After E, the first (upper) half is S'_j + M_j and the lower half is S'_{v+j}.
    Both message shifts and E are bijections, so this inverse is total.
    """
    if len(message) != variant.block_words or len(output) != variant.words:
        raise ValueError("wrong vector length")
    mask = variant.mask
    post = output.copy()
    for j, m in enumerate(message):
        post[j] = (post[j] - m) & mask
    pre = permutation_inverse(post, variant)
    flag_word = variant.words - 1 if flag_last else 0
    pre[flag_word] ^= flag
    state = pre.copy()
    for j, m in enumerate(message):
        state[variant.block_words + j] = (state[variant.block_words + j] - m) & mask
    return state


def initial_state(variant: Variant, *, flag_last: bool = False) -> list[int]:
    raw = [0] * variant.words
    raw[0] = variant.iv_word0
    return compression([0] * variant.block_words, raw, variant, 0, flag_last=flag_last)


def bits_to_words(data: bytes, width: int) -> list[int]:
    """Interpret a byte-sized diagnostic input as little-endian words.

    The paper specifies word and digest little-endian encoding, but does not
    give a complete external byte-stream KAT in the supplied PDF.
    """
    if len(data) % (width // 8):
        raise ValueError("diagnostic input must be word-aligned")
    return [int.from_bytes(data[i:i + width // 8], "little") for i in range(0, len(data), width // 8)]


def words_to_hex(words: Iterable[int], width: int) -> str:
    return "".join(f"{w:0{width // 4}x}" for w in words)


def bytes_to_bits(data: bytes) -> list[int]:
    # A[i] is bit i of a little-endian word, so bytes are expanded LSB first.
    return [(byte >> i) & 1 for byte in data for i in range(8)]


def bits_to_int_lsb(bits: Iterable[int]) -> int:
    value = 0
    for i, bit in enumerate(bits):
        value |= bit << i
    return value


def int_to_bits_lsb(value: int, count: int) -> list[int]:
    return [(value >> i) & 1 for i in range(count)]


def pad_bits(message: list[int], block_bits: int) -> list[int]:
    if len(message) >= 1 << 128:
        raise ValueError("bit length does not fit the specified 128-bit field")
    remainder = len(message) % block_bits
    zeros = 2 * block_bits - 129 - remainder
    return message + [1] + [0] * zeros + int_to_bits_lsb(len(message), 128)


def bits_to_blocks(bits: list[int], block_bits: int, width: int) -> list[list[int]]:
    if len(bits) % block_bits:
        raise ValueError("padded input is not block aligned")
    blocks = []
    for pos in range(0, len(bits), block_bits):
        block = bits[pos:pos + block_bits]
        blocks.append([bits_to_int_lsb(block[i:i + width]) for i in range(0, block_bits, width)])
    return blocks


def qsh_hash_bits(message: list[int], variant: Variant, *, flag_last: bool = False) -> list[int]:
    block_words = bits_to_blocks(
        pad_bits(message, variant.block_words * variant.width),
        variant.block_words * variant.width,
        variant.width,
    )
    chunks = [block_words[i:i + 16] for i in range(0, len(block_words), 16)]
    h0 = initial_state(variant, flag_last=flag_last)

    def chunk_cv(chunk: list[list[int]], only: bool) -> list[int]:
        state = h0
        for i, block in enumerate(chunk):
            flag = 0
            if i == 0:
                flag |= CHUNK_START
            if i == len(chunk) - 1:
                flag |= CHUNK_END
                if only:
                    flag |= ROOT
            state = compression(block, state, variant, flag, flag_last=flag_last)
        return state[:variant.cv_words]

    def parent_cv(left: list[int], right: list[int], root: bool) -> list[int]:
        flag = PARENT | (ROOT if root else 0)
        out = compression(left + right, h0, variant, flag, flag_last=flag_last)
        return out[:variant.cv_words]

    def build(cvs: list[list[int]], root: bool) -> list[int]:
        if len(cvs) == 1:
            return cvs[0]
        # Unique left-full split: the largest power of two smaller than len(cvs).
        left_size = 1 << ((len(cvs) - 1).bit_length() - 1)
        left = build(cvs[:left_size], False) if left_size > 1 else cvs[0]
        right_size = len(cvs) - left_size
        right = build(cvs[left_size:], False) if right_size > 1 else cvs[left_size]
        return parent_cv(left, right, root)

    root_cv = chunk_cv(chunks[0], len(chunks) == 1) if len(chunks) == 1 else build(
        [chunk_cv(chunk, False) for chunk in chunks], True
    )
    root_bits = [
        bit
        for word in root_cv
        for bit in int_to_bits_lsb(word, variant.width)
    ]
    return root_bits[:variant.digest_bits]


def qsh_hash_bytes(message: bytes, variant: Variant, *, flag_last: bool = False) -> bytes:
    bits = qsh_hash_bits(bytes_to_bits(message), variant, flag_last=flag_last)
    return bytes(bits_to_int_lsb(bits[i:i + 8]) for i in range(0, len(bits), 8))


def free_start_collision(variant: Variant, *, flag_last: bool = False) -> tuple[list[int], list[int], list[int], list[int]]:
    """Return two (M,H) pairs mapping to the all-zero chaining state."""
    message_a = [0] * variant.block_words
    message_b = [0] * variant.block_words
    message_b[0] = 1
    flag = PARENT
    output = [0] * variant.words
    state_a = compression_inverse(output, message_a, variant, flag, flag_last=flag_last)
    state_b = compression_inverse(output, message_b, variant, flag, flag_last=flag_last)
    return message_a, state_a, message_b, state_b


if __name__ == "__main__":
    for variant in (QSH512, QSH768, QSH1024):
        zero = [0] * variant.words
        assert permutation_inverse(permutation(zero, variant), variant) == zero
        probe = [i & variant.mask for i in range(1, variant.words + 1)]
        assert permutation_inverse(permutation(probe, variant), variant) == probe
        print(variant.name, "permutation inverse checks passed", words_to_hex(permutation(probe, variant)[:4], variant.width))
        ma, ha, mb, hb = free_start_collision(variant)
        assert ma != mb and (ha, ma) != (hb, mb)
        assert compression(ma, ha, variant, PARENT) == compression(mb, hb, variant, PARENT) == [0] * variant.words
        assert compression_inverse(compression(ma, ha, variant, PARENT), ma, variant, PARENT) == ha
        print(variant.name, "free-start collision verified")
        print("  M_a =", words_to_hex(ma, variant.width))
        print("  H_a =", words_to_hex(ha, variant.width))
        print("  M_b =", words_to_hex(mb, variant.width))
        print("  H_b =", words_to_hex(hb, variant.width))
        digest_a = qsh_hash_bytes(b"abc", variant, flag_last=False)
        digest_b = qsh_hash_bytes(b"abc", variant, flag_last=True)
        print(variant.name, "flag-at-word-0", digest_a.hex())
        print(variant.name, "flag-at-last-word", digest_b.hex())
