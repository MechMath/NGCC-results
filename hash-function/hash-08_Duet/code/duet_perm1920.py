#!/usr/bin/env python3
"""Reference word-level implementation of Duet f-1920 for audit experiments."""

MASK64 = (1 << 64) - 1

SBOX = (
    0x1A, 0x09, 0x10, 0x17, 0x07, 0x08, 0x15, 0x0E,
    0x19, 0x1F, 0x1E, 0x0C, 0x1B, 0x01, 0x04, 0x0A,
    0x05, 0x13, 0x0D, 0x0F, 0x16, 0x1C, 0x06, 0x18,
    0x11, 0x12, 0x14, 0x03, 0x1D, 0x02, 0x00, 0x0B,
)

V30 = (
    1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1,
    1, 1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0,
)

C1_1920 = (
    0xB7E151628AED2A6A, 0xBF7158809CF4F3C7, 0x62E7160F38B4DA56,
    0xA784D9045190CFEF, 0x324E7738926CFBE5, 0xF4BF8D8D8C31D763,
    0xDA06C80ABB1185EB, 0x4F7C7B5757F59584, 0x90CFD47D7C19BB42,
    0x158D9554F7B46BCE, 0xD55C4D79FD5F24D6, 0x613C31C3839A2DDF,
    0x8A9A276BCFBFA1C8, 0x77C56284DAB79CD4, 0xC2B3293D20E9E5EA,
    0xF02AC60ACC93ED87, 0x4422A52ECB238FEE, 0xE5AB6ADD835FD1A0,
)


def rotl(x: int, n: int) -> int:
    n %= 64
    return ((x << n) | (x >> (64 - n))) & MASK64


def substitute(state):
    out = [0] * 30
    for j in range(6):
        for k in range(64):
            u = 0
            for i in range(5):
                u = (u << 1) | ((state[5 * j + i] >> (63 - k)) & 1)
            y = SBOX[u]
            for i in range(5):
                out[5 * j + i] |= ((y >> (4 - i)) & 1) << (63 - k)
    return out


def mix_slice(state):
    return [
        state[j] ^ state[(j + 3) % 30] ^ state[(j + 10) % 30]
        ^ state[(j + 13) % 30] ^ state[(j + 14) % 30] ^ state[(j + 15) % 30]
        ^ state[(j + 16) % 30] ^ state[(j + 18) % 30] ^ state[(j + 21) % 30]
        ^ state[(j + 26) % 30] ^ state[(j + 28) % 30]
        for j in range(30)
    ]


def mix_lane(state):
    return [rotl(x, t) ^ rotl(x, t + 21) ^ rotl(x, t + 43) for t, x in enumerate(state)]


def f1920(state, constants):
    assert len(state) == 30
    assert len(constants) in (12, 18)
    state = list(state)
    for constant in constants:
        state = substitute(state)
        state = mix_slice(state)
        state[0] ^= constant
        state = mix_lane(state)
    return state


def zero_message_input(length: int):
    """One-block f1 input for an all-zero message of the given length."""
    assert 0 <= length <= 767
    words = [0] * 30
    words[length // 64] |= 1 << (63 - (length % 64))
    return words


def main() -> None:
    x = f1920(zero_message_input(0), C1_1920)
    i1024 = (0, 0, 0, x[0], 0, 0, 0, 0, 0, 0, 0, 0) + tuple(x[12:30])
    i768 = tuple([0, 0, 0, x[0], 0, 0, 0, 0, 0, 0, 0, 0] + [0] * 5) + tuple(x[17:30])
    print("f1(M=0) state words:", [f"{v:016x}" for v in x])
    print("f2 inputs equal:", i768 == i1024)


if __name__ == "__main__":
    main()
