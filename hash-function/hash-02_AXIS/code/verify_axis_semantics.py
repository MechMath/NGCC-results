#!/usr/bin/env python3
"""Independent exact witness for AXIS-512's two literal beat semantics."""

CONSTANTS = [
    0x243F6A8885A308D3B7E151628AED2A6A9E3779B97F4A7C15,
    0x7160C6B758B90A76D81F8650363C93F849CA76E19F938DA4,
    0x70FF7724ACB762F7B54CBDE35B659CC7CD71C257B752EEB5,
    0x4FD6E6B4FBAB7ECD3120355B0549D6B947EA14CFA7D43857,
    0x6B634EF404919AAA03F92D7B7FAEEF105DCD2735332E4029,
    0x53C1A2C96C4DE7E3CD0814056FA6E00BD57AC41E845348D4,
    0xF3FF90522F99DAE5352FF6633C6EFBA6ABDBF53A09476735,
    0xB1A270D3653FB5B8D94570230179F8120D875B906F276D2C,
]

# The PDF prints ExL and UpL high-to-low.  These lists are index 0 to 5/6.
EXL = [0, 12, 32, 96, 107, 125, 11]
UPL = [66, 75, 90, 162, 178, 188]


def bit(word: int, index: int) -> int:
    return (word >> index) & 1


def sbox(x5: int, x4: int, x3: int, x2: int, x1: int, x0: int) -> int:
    return x5 * x4 ^ x3 * x2 ^ x1 * x0


def update_register(state: list[int], j: int, message_bit: int) -> int:
    current = state[j]
    tau = sbox(
        bit(state[(j + 5) % 8], EXL[3]),
        bit(state[(j + 5) % 8], EXL[2]),
        bit(state[(j + 3) % 8], EXL[5]),
        bit(state[(j + 3) % 8], EXL[1]),
        bit(state[(j + 1) % 8], EXL[4]),
        bit(state[(j + 1) % 8], EXL[0]),
    )
    control = (
        message_bit
        ^ sbox(
            bit(current, EXL[5]),
            bit(current, EXL[2]),
            bit(current, EXL[4]),
            bit(current, EXL[1]),
            bit(current, EXL[3]),
            bit(current, EXL[0]),
        )
        ^ tau
        ^ bit(state[(j - 1) % 8], EXL[6])
    )
    t0 = bit(current, EXL[2]) ^ bit(current, EXL[1]) ^ bit(current, EXL[0]) ^ control
    t1 = bit(current, EXL[5]) ^ bit(current, EXL[4]) ^ bit(current, EXL[3]) ^ control
    result = current
    for i in UPL[2], UPL[1], UPL[0]:
        result ^= t1 << i
    for i in UPL[5], UPL[4], UPL[3]:
        result ^= t0 << i
    return ((result << 1) & ((1 << 192) - 1)) | (result >> 191)


def full_update(state: list[int], mu: int, nu: int, snapshot: bool) -> list[int]:
    if snapshot:
        old = state[:]
        return [
            update_register(old, j, mu if j % 2 == 0 else nu)
            for j in range(8)
        ]
    state = state[:]
    for j in range(8):
        state[j] = update_register(state, j, mu if j % 2 == 0 else nu)
    return state


def full_controls(state: list[int], controls: list[int], snapshot: bool) -> list[int]:
    if snapshot:
        old = state[:]
        return [update_register(old, j, controls[j]) for j in range(8)]
    state = state[:]
    for j in range(8):
        state[j] = update_register(state, j, controls[j])
    return state


def empty_padding() -> list[int]:
    # Displayed MSB-to-LSB: 1 0^62 1 Binary64(0).  Reverse to stream index.
    displayed = [1] + [0] * 62 + [1] + [0] * 64
    return list(reversed(displayed))


def constant_stream() -> list[int]:
    return [
        bit(CONSTANTS[(i % 1536) // 192], i % 192)
        for i in range(8 * (1024 + 256))
    ]


def axis512_empty(snapshot: bool) -> list[int]:
    state = CONSTANTS[:]
    padded = empty_padding()
    assert len(padded) == 128
    for i in range(0, len(padded), 2):
        state = full_update(state, padded[i + 1], padded[i], snapshot)

    controls = constant_stream()
    for beat in range(1024):
        byte = controls[8 * beat:8 * beat + 8]
        state = full_controls(state, byte, snapshot)

    digest = []
    for beat in range(256):
        digest.append(
            bit(state[6], 0)
            ^ bit(state[4], 0)
            ^ (bit(state[2], 0) & bit(state[0], 0))
        )
        digest.append(
            bit(state[7], 0)
            ^ bit(state[5], 0)
            ^ (bit(state[3], 0) & bit(state[1], 0))
        )
        byte = controls[8 * (1024 + beat):8 * (1024 + beat) + 8]
        # ReUpFull uses c_j for register j.
        state = full_controls(state, byte, snapshot)
    return digest


def to_hex(stream_bits: list[int]) -> str:
    """Display HV=h_255||...||h_0, preserving each h_mu||h_nu word."""
    assert len(stream_bits) % 2 == 0
    words = [stream_bits[i:i + 2] for i in range(0, len(stream_bits), 2)]
    displayed = [b for word in reversed(words) for b in word]
    return "".join(
        f"{sum(displayed[i + k] << (7 - k) for k in range(8)):02x}"
        for i in range(0, len(displayed), 8)
    )


def main() -> None:
    snapshot = axis512_empty(True)
    ascending = axis512_empty(False)
    expected_snapshot = (
        "1c24e974658d83e73404ccee12b8bb96bb9027fe3e745e60"
        "485f1710c39e14a887ba5a6d25155ff0ca47fe0290475cde"
        "b1b5c30d84f661c5bae37942395e4518"
    )
    expected_ascending = (
        "221fc82aabf4aece59322c5e77723bad521d6f7e9575493f"
        "88aa3a7d68e7be46c50f86987c5445830c1c34f3617ce93a"
        "f049bd3be3d4e2774b297cf1f41d8a46"
    )
    assert to_hex(snapshot) == expected_snapshot
    assert to_hex(ascending) == expected_ascending
    assert snapshot[0] == 0 and ascending[0] == 1
    print("verified")
    print("first_digest_bit", snapshot[0], ascending[0])
    print("snapshot", expected_snapshot)
    print("ascending", expected_ascending)


if __name__ == "__main__":
    main()
