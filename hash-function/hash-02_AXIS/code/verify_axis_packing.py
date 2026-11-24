#!/usr/bin/env python3
"""Independent literal AXIS implementation for the one-byte input 0x01.

Registers are 192-bit integers.  AXIS bit index zero is the least significant
bit, matching the specification's right-to-left indexing convention.
"""

MASK192 = (1 << 192) - 1

CONSTANTS = [
    int("243F6A8885A308D3B7E151628AED2A6A9E3779B97F4A7C15", 16),
    int("7160C6B758B90A76D81F8650363C93F849CA76E19F938DA4", 16),
    int("70FF7724ACB762F7B54CBDE35B659CC7CD71C257B752EEB5", 16),
    int("4FD6E6B4FBAB7ECD3120355B0549D6B947EA14CFA7D43857", 16),
    int("6B634EF404919AAA03F92D7B7FAEEF105DCD2735332E4029", 16),
    int("53C1A2C96C4DE7E3CD0814056FA6E00BD57AC41E845348D4", 16),
    int("F3FF90522F99DAE5352FF6633C6EFBA6ABDBF53A09476735", 16),
    int("B1A270D3653FB5B8D94570230179F8120D875B906F276D2C", 16),
]

# Python index k below is the paper's array index k, whose indexing runs from
# right to left.  Thus EXL[0]=0 and UPL[0]=66.
EXL = (0, 12, 32, 96, 107, 125, 11)
UPL = (66, 75, 90, 162, 178, 188)


def bit(x, i):
    return (x >> i) & 1


def xor_bits(x, positions):
    out = 0
    for i in positions:
        out ^= bit(x, i)
    return out


def nonlinear(a, b, c):
    # Arguments a,b,c are 2-bit strings.  This is x5*x4 ^ x3*x2 ^ x1*x0.
    return ((a >> 1) & a & 1) ^ ((b >> 1) & b & 1) ^ ((c >> 1) & c & 1)


def ror192(x, n=1):
    return ((x >> n) | (x << (192 - n))) & MASK192


def up_res(state, j, m):
    def get(k, i):
        return bit(state[(j + k) % 8], i)

    a = (get(5, EXL[3]) << 1) | get(5, EXL[2])
    b = (get(3, EXL[5]) << 1) | get(3, EXL[1])
    c = (get(1, EXL[4]) << 1) | get(1, EXL[0])
    tau = nonlinear(a, b, c)

    selected = [EXL[5], EXL[2], EXL[4], EXL[1], EXL[3], EXL[0]]
    sx = 0
    for i in selected:
        sx = (sx << 1) | get(0, i)
    sb = ((sx >> 5) & (sx >> 4) & 1) ^ ((sx >> 3) & (sx >> 2) & 1) ^ ((sx >> 1) & sx & 1)

    new_b = m ^ sb ^ tau ^ get(-1, EXL[6])
    t0 = get(0, EXL[2]) ^ get(0, EXL[1]) ^ get(0, EXL[0]) ^ new_b
    t1 = get(0, EXL[5]) ^ get(0, EXL[4]) ^ get(0, EXL[3]) ^ new_b
    reg = state[j]
    for i in (UPL[2], UPL[1], UPL[0]):
        reg ^= t1 << i
    for i in (UPL[5], UPL[4], UPL[3]):
        reg ^= t0 << i
    state[j] = ror192(reg)


def up_full(state, mu, nu):
    for j in range(8):
        up_res(state, j, mu if j % 2 == 0 else nu)


def reup_full(state, byte):
    # byte is c7...c0 left-to-right.
    for j in range(8):
        up_res(state, j, (byte >> j) & 1)


def gen_digest(state):
    hu = bit(state[6], 0) ^ bit(state[4], 0) ^ (bit(state[2], 0) & bit(state[0], 0))
    hv = bit(state[7], 0) ^ bit(state[5], 0) ^ (bit(state[3], 0) & bit(state[1], 0))
    return hu, hv


def binary64(n):
    return [int(c) for c in format(n, "064b")]


def padded_message_one_byte():
    # The message byte 0x01 is bitstring 00000001 under the ICCS MSB-first rule.
    message = [0, 0, 0, 0, 0, 0, 0, 1]
    n = len(message)
    s = (-n - 3) % 64
    return message + [1] + [0] * (s + 1) + [1] + binary64(n)


def constant_stream(total_beats):
    # C = ... || initS || initS.  The least significant byte of initS is
    # Constant0[7..0], so consume bytes from register zero upward and repeat.
    init_bytes = []
    for c in CONSTANTS:
        for shift in range(0, 192, 8):
            init_bytes.append((c >> shift) & 0xFF)
    return (init_bytes * ((total_beats + len(init_bytes) - 1) // len(init_bytes)))[:total_beats]


def axis(d):
    state = CONSTANTS.copy()
    msg = padded_message_one_byte()
    pos = 0 if MESSAGE_LEFT else len(msg)

    def take(count):
        nonlocal pos
        value = 0
        if MESSAGE_LEFT:
            assert pos + count <= len(msg)
            for _ in range(count):
                value = (value << 1) | msg[pos]
                pos += 1
        else:
            assert pos >= count
            for k in range(count):
                pos -= 1
                value |= msg[pos] << k
        return value

    if d == 512:
        n_me = len(msg) // 2
        uses_two = [True] * n_me
    elif d == 768:
        r = len(msg) % 192
        extra = {0: 0, 64: 64, 128: 32}[r]
        n_me = (2 * len(msg) + extra) // 3
        uses_two = []
        for i in range(n_me):
            tail_duplicate = ((r == 64 and i >= n_me - 64) or
                              (r == 128 and i >= n_me - 32))
            uses_two.append((i % 2 == 1) and not tail_duplicate)
    elif d == 1024:
        n_me = len(msg)
        uses_two = [False] * n_me
    else:
        raise ValueError(d)

    for i in range(n_me):
        if d == 512:
            x = take(2)
            up_full(state, x >> 1, x & 1)
        elif d == 768:
            if uses_two[i]:
                x = take(2)
                up_full(state, x >> 1, x & 1)
            else:
                x = take(1)
                up_full(state, x, x)
        else:
            x = take(1)
            up_full(state, x, x)
    assert pos == (len(msg) if MESSAGE_LEFT else 0)

    n_dig = {512: 256, 768: 512, 1024: 1024}[d]
    cbytes = constant_stream(1024 + n_dig)
    ci = 0
    for _ in range(1024):
        reup_full(state, cbytes[ci])
        ci += 1

    beat_outputs = []
    for i in range(n_dig):
        hu, hv = gen_digest(state)
        if d == 512:
            beat_outputs.append((hu << 1) | hv)
        elif d == 768:
            beat_outputs.append(((hu << 1) | hv) if i % 2 else (hu,) )
        else:
            beat_outputs.append((hu,))
        reup_full(state, cbytes[ci])
        ci += 1

    # Algorithm 1 concatenates h_(NDigGen-1) through h_0.  Within a two-bit
    # h_i the paper's notation is h_mu || h_nu, with h_mu leftmost.
    semantic = []
    beat_order = reversed(beat_outputs) if OUTPUT_BEATS_REVERSE else beat_outputs
    for out in beat_order:
        if isinstance(out, tuple):
            semantic.extend(out)
        else:
            pair = ((out >> 1) & 1, out & 1)
            semantic.extend(reversed(pair) if OUTPUT_PAIR_SWAP else pair)
    return semantic


MESSAGE_LEFT = False
OUTPUT_BEATS_REVERSE = True
OUTPUT_PAIR_SWAP = False


def packed(prefix_bits, order):
    result = []
    for i in range(0, len(prefix_bits) // 8):
        bits = prefix_bits[8 * i:8 * i + 8]
        byte = 0
        for k, b in enumerate(bits):
            if order == "B7":
                byte |= b << (7 - k)
            elif order == "B0":
                byte |= b << k
            else:
                raise ValueError(order)
        result.append(byte)
    return result


if __name__ == "__main__":
    for d in (512, 768, 1024):
        bits = axis(d)
        print(d, "".join(map(str, bits[:32])))
        print("B7", bytes(packed(bits, "B7")[:8]).hex())
        print("B0", bytes(packed(bits, "B0")[:8]).hex())
