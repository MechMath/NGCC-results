#!/usr/bin/env python3
"""Exact working model of the pinned Thunder specification.

This is a research note, not execution evidence. It keeps the bit ordering
S[64*(5*y+x)+z] = D[x][y][z] used by the submitted specification.
"""

from __future__ import annotations

from functools import reduce


N = 1600
LANE_MASK = (1 << 64) - 1

RHO = {
    (0, 0): 45, (1, 0): 33, (2, 0): 13, (3, 0): 1, (4, 0): 27,
    (0, 1): 40, (1, 1): 52, (2, 1): 19, (3, 1): 47, (4, 1): 9,
    (0, 2): 34, (1, 2): 5, (2, 2): 0, (3, 2): 2, (4, 2): 37,
    (0, 3): 48, (1, 3): 30, (2, 3): 61, (3, 3): 8, (4, 3): 38,
    (0, 4): 6, (1, 4): 18, (2, 4): 49, (3, 4): 17, (4, 4): 43,
}
THETA_Y = [41, 50, 6, 10, 27]
ROUND_CONSTANTS = [
    0x0000000000000001, 0x0000000000000003, 0x000000000000000A,
    0x0000000000000088, 0x0000000000008081, 0x0000000000008002,
    0x0000000000000009, 0x0000000000000083, 0x000000000000800A,
    0x0000000000000089, 0x0000000000008083, 0x000000000000800B,
]


def idx(x: int, y: int, z: int) -> int:
    return 64 * (5 * y + x) + (z % 64)


def bit(state: int, x: int, y: int, z: int) -> int:
    return (state >> idx(x, y, z)) & 1


def rho(state: int) -> int:
    out = 0
    for x in range(5):
        for y in range(5):
            shift = RHO[x, y]
            for z in range(64):
                if bit(state, x, y, z + shift):
                    out |= 1 << idx(x, y, z)
    return out


def theta(state: int) -> int:
    parity = [[0] * 64 for _ in range(5)]
    shifted_parity = [[0] * 64 for _ in range(5)]
    for x in range(5):
        for z in range(64):
            parity[x][z] = reduce(
                int.__xor__, (bit(state, x, y, z) for y in range(5))
            )
            shifted_parity[x][z] = reduce(
                int.__xor__,
                (bit(state, x, y, z + THETA_Y[y]) for y in range(5)),
            )
    e = [
        [
            parity[x][z] ^ parity[(x - 1) % 5][(z + 1) % 64]
            for z in range(64)
        ]
        for x in range(5)
    ]
    f = [
        [
            shifted_parity[(x + 1) % 5][z]
            ^ shifted_parity[(x - 2) % 5][(z + 36) % 64]
            for z in range(64)
        ]
        for x in range(5)
    ]
    out = 0
    for x in range(5):
        for y in range(5):
            for z in range(64):
                value = (
                    bit(state, x, y, z)
                    ^ e[x][(z + 26) % 64]
                    ^ f[x][(z + 26 + THETA_Y[y]) % 64]
                )
                if value:
                    out |= 1 << idx(x, y, z)
    return out


def pi(state: int) -> int:
    out = 0
    for x in range(5):
        for y in range(5):
            out_x = y
            out_y = (2 * x + 3 * y + 2) % 5
            for z in range(64):
                if bit(state, x, y, z):
                    out |= 1 << idx(out_x, out_y, z)
    return out


def iota(state: int, round_index: int) -> int:
    return state ^ ROUND_CONSTANTS[round_index]


def linear_part(state: int) -> int:
    return pi(theta(rho(state)))


def psi_lane(value: int) -> int:
    a = [(value >> i) & 1 for i in range(5)]
    out = []
    for y in range(5):
        product = (
            (1 - a[(y + 1) % 5])
            * a[(y + 2) % 5]
            * (1 - a[(y + 4) % 5])
        )
        out.append(a[(y + 3) % 5] ^ product)
    return sum(out[i] << i for i in range(5))


PSI_TABLE = [psi_lane(i) for i in range(32)]


def psi(state: int) -> int:
    out = 0
    for x in range(5):
        for z in range(64):
            value = sum(bit(state, x, y, z) << y for y in range(5))
            mapped = PSI_TABLE[value]
            for y in range(5):
                if (mapped >> y) & 1:
                    out |= 1 << idx(x, y, z)
    return out


def permutation(state: int) -> int:
    for round_index in range(12):
        state = psi(pi(theta(rho(iota(state, round_index)))))
    return state


def lane(state: int, x: int, y: int) -> int:
    return (state >> (64 * (5 * y + x))) & LANE_MASK


def make_inverse_linear_part() -> list[int]:
    """Rows [source coefficients | output-basis coefficients] for L^-1."""
    rows = [0] * N
    for source_bit in range(N):
        image = linear_part(1 << source_bit)
        while image:
            low = image & -image
            output_bit = low.bit_length() - 1
            rows[output_bit] |= 1 << source_bit
            image ^= low
    for output_bit in range(N):
        rows[output_bit] |= 1 << (N + output_bit)
    for column in range(N):
        pivot = next(
            row for row in range(column, N) if (rows[row] >> column) & 1
        )
        rows[column], rows[pivot] = rows[pivot], rows[column]
        for row in range(N):
            if row != column and (rows[row] >> column) & 1:
                rows[row] ^= rows[column]
    return rows


INVERSE_LINEAR_ROWS = make_inverse_linear_part()
LINEAR_IMAGES = [linear_part(1 << source_bit) for source_bit in range(N)]
STATE_MASK = (1 << N) - 1


def inverse_linear_part(target: int) -> int:
    out = 0
    for row in INVERSE_LINEAR_ROWS:
        if ((row >> N) & target).bit_count() & 1:
            out ^= row & STATE_MASK
    return out


def local_psi_collision_difference(x: int, z: int, difference: int) -> int:
    return sum(
        ((difference >> y) & 1) << idx(x, y, z) for y in range(5)
    )


FIXED = {
    "Thunder-512": {
        "h": 512, "c": 576, "r": 1024, "nc": 9, "nr": 16,
        "iv": [
            0xBF6F0F35E3B4B690, 0x8E265B9343C855BE, 0x246B722CBB56513A,
            0xBC2F395FD06923B4, 0xDD524527A77295D2, 0x41E818D4F5A362FC,
            0x694AD1341F066571, 0x9B04C99DC477B767, 0x385EC0E6C2C9262C,
        ],
    },
    "Thunder-768": {
        "h": 768, "c": 832, "r": 768, "nc": 13, "nr": 12,
        "iv": [
            0x1EE2C8609716E1FD, 0x9C67610B0EF5484C, 0x1E6D7FF8F050881C,
            0xCC3FA3279D6371F6, 0xDB34E00BB8122876, 0xB9839A4AF0CAE3D5,
            0xDCFA816272A35C8C, 0x55FBD3148A3A352A, 0x900E93CA9A4A9953,
            0x9CCCEF7ACDC19758, 0xA7A16EAC10689E8C, 0x676B3791EBA6281C,
            0xE1F7C9010E8EC178,
        ],
    },
    "Thunder-1024": {
        "h": 1024, "c": 1088, "r": 512, "nc": 17, "nr": 8,
        "iv": [
            0xF40BA520BF2176AF, 0x6CA062C126D8F82F, 0xDE0AF08D84B563FD,
            0x9DE9EBB8E116C786, 0x0E88F98C2AFD6C77, 0xCC6BB54C5AB31102,
            0x92814BCC238CCEBA, 0x6AF2AB07A720737F, 0x95D75D8EE27A1149,
            0x9F76C65C5E81FEAD, 0xF201204809F567F0, 0x717EF7874FDF8324,
            0x1E74332499E4122A, 0xF8935180A66B22D6, 0x948CDBECC8BAE9D8,
            0x2C44DD200F6D93DE, 0x24503F60BF3CA4C8,
        ],
    },
}

XOF = {
    "Thunder-XOF-256": {
        "c": 576, "r": 1024, "squeeze": 1280, "nc": 9, "nu_min": 256,
        "iv": [
            0x9E812DA2738FE002, 0x219B7C0760B0E94D, 0x52156057D367DA1E,
            0x00A5215DFFDE8879, 0xA7883EF829CC1A87, 0x4A515E2B8E01C2FF,
            0x5C0AE2159E01FC77, 0x729855614D7F148C, 0x4980F7D439055835,
        ],
    },
    "Thunder-XOF-384": {
        "c": 832, "r": 768, "squeeze": 1152, "nc": 13, "nu_min": 384,
        "iv": [
            0xF45C092FAC272ECD, 0x6663F2D34B981CE9, 0x3F8ADB0DCF6E3C57,
            0xF4E8D96C8C2AA889, 0xF63C53A3C826DD36, 0x6322E49D1D66FD68,
            0xA69B502F299DF9E8, 0x37F1F11B1F666C79, 0x93B2116B09264243,
            0x103353E2853DC514, 0x03BF159A8C56AEEA, 0x63A3C93B73413AB0,
            0x12213C610D4668BF,
        ],
    },
    "Thunder-XOF-512": {
        "c": 1088, "r": 512, "squeeze": 1024, "nc": 17, "nu_min": 512,
        "iv": [
            0xC2884D525C702B64, 0x66A72645A0F40A18, 0xBAB84A614A2350C9,
            0xF081647F0AD178DD, 0x7B767D98DA24EC2C, 0x3B3C04DD07203847,
            0xFA818BD5EB11B50C, 0xD5E7B03035AB65EF, 0x3E1620F081AF14FA,
            0x621BC66649423A58, 0x9DE98219698CF8DD, 0x01C0349676559785,
            0x0CB97494B14EA9E1, 0x9A48816B41176EB4, 0x7EECDF54AA725D35,
            0xFFF86452843778BC, 0x9AEEEF2B632AA55E,
        ],
    },
}


def iv_state(values: list[int]) -> int:
    return sum(value << (64 * i) for i, value in enumerate(values))


def linear_solve(rows: list[tuple[int, int]], width: int) -> int | None:
    """Solve rows [(coefficients, rhs)] over GF(2), with free vars set to zero."""
    augmented = [coefficients | (rhs << width) for coefficients, rhs in rows]
    rank = 0
    pivots = []
    coefficient_mask = (1 << width) - 1
    for column in range(width):
        pivot = next(
            (
                row for row in range(rank, len(augmented))
                if (augmented[row] >> column) & 1
            ),
            None,
        )
        if pivot is None:
            continue
        augmented[rank], augmented[pivot] = augmented[pivot], augmented[rank]
        for row in range(len(augmented)):
            if row != rank and (augmented[row] >> column) & 1:
                augmented[row] ^= augmented[rank]
        pivots.append(column)
        rank += 1
    if any(
        not (row & coefficient_mask) and ((row >> width) & 1)
        for row in augmented
    ):
        return None
    solution = 0
    for row, column in enumerate(pivots):
        if (augmented[row] >> width) & 1:
            solution |= 1 << column
    return solution


def first_block_collision(instance: dict) -> tuple[int, int]:
    """Rejected candidate retained only to prevent the misreading being repeated.

    The input difference is all bits in row y=4. Linear propagation sends it to
    difference 0x1f in every S-box at x=4. Solve for a base state whose values at
    those S-boxes are all zero; its partner has all 0x1f values.

    The candidate is invalid: the PDF complements only the y+1 and y+4 factors,
    giving psi(0)=0 and psi(0x1f)=0x1f, not a collision.
    """
    nc = instance["nc"]
    rate_start = 64 * nc
    rate_width = N - rate_start
    capacity = iv_state(instance["iv"])
    constant = linear_part(iota(capacity, 0))
    target_bits = [idx(4, y, z) for z in range(64) for y in range(5)]
    rows = []
    for output_bit in target_bits:
        coefficients = 0
        for rate_bit in range(rate_width):
            image = LINEAR_IMAGES[rate_start + rate_bit]
            if (image >> output_bit) & 1:
                coefficients |= 1 << rate_bit
        rows.append((coefficients, (constant >> output_bit) & 1))
    base_rate = linear_solve(rows, rate_width)
    if base_rate is None:
        raise ValueError("the target S-box linear system is inconsistent")
    base = capacity | (base_rate << rate_start)
    delta = sum(LANE_MASK << (64 * (20 + x)) for x in range(5))
    partner = base ^ delta
    if PSI_TABLE[0] != PSI_TABLE[0x1F]:
        raise ValueError("rejected non-bijectivity route: psi is bijective")
    return base, partner


def absorb_nonfinal(state: int, block: int, nc: int) -> int:
    capacity_bits = 64 * nc
    x = state ^ (block << capacity_bits)
    return permutation(x) ^ (x & ((1 << capacity_bits) - 1))


def absorb_final(state: int, block: int, nc: int) -> int:
    capacity_bits = 64 * nc
    x = state ^ (block << capacity_bits) ^ 1
    return permutation(x) ^ (x & ((1 << capacity_bits) - 1))


def fixed_hash(message: bytes, instance: dict) -> bytes:
    r = instance["r"]
    nc = instance["nc"]
    if len(message) * 8 > 1 << 64:
        raise ValueError("message exceeds the submitted 2^64-bit limit")
    complete, remainder = divmod(len(message), r // 8)
    blocks = []
    for block_index in range(complete):
        start = block_index * (r // 8)
        blocks.append(int.from_bytes(message[start:start + (r // 8)], "little"))
    tail = message[complete * (r // 8):]
    padded = tail + b"\x80"
    while len(padded) % (r // 8):
        padded += b"\x00"
    blocks.extend(
        int.from_bytes(padded[i:i + (r // 8)], "little")
        for i in range(0, len(padded), r // 8)
    )
    state = iv_state(instance["iv"])
    for block in blocks[:-1]:
        state = absorb_nonfinal(state, block, nc)
    state = absorb_final(state, blocks[-1], nc)
    return state.to_bytes(N // 8, "little")[:instance["h"] // 8]


if __name__ == "__main__":
    print("psi_table", PSI_TABLE)
    print("psi_image_size", len(set(PSI_TABLE)))
    print("psi_collisions", sorted(
        (a, b) for a in range(32) for b in range(a)
        if PSI_TABLE[a] == PSI_TABLE[b]
    ))
