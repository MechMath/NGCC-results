from collections import Counter
from math import gcd

S = [3, 0, 6, 2, 5, 4, 15, 14, 10, 8, 7, 9, 1, 12, 13, 11]
PL = [28, 18, 16, 26, 30, 22, 29, 23, 27, 17, 24, 31, 25, 19, 21, 20,
      3, 10, 4, 15, 14, 5, 7, 13, 12, 0, 11, 1, 9, 2, 6, 8]
PR = [0, 2, 1, 12, 11, 8, 13, 7, 10, 4, 6, 5, 3, 14, 9, 15,
      22, 18, 27, 23, 24, 31, 20, 28, 29, 17, 16, 19, 25, 30, 26, 21]
F = [11, 3, 14, 2, 9, 10, 12, 0, 4, 13, 7, 8, 15, 6, 5, 1,
     16, 19, 27, 22, 31, 26, 20, 30, 23, 29, 25, 18, 24, 21, 28, 17]
G = [23, 3, 31, 2, 0, 20, 21, 15, 13, 29, 14, 30, 12, 28, 22, 1,
     17, 24, 8, 5, 27, 16, 6, 11, 25, 18, 19, 10, 7, 9, 26, 4]


def cycles(p):
    out = []
    seen = set()
    for i in range(len(p)):
        if i in seen:
            continue
        c = []
        j = i
        while j not in seen:
            seen.add(j)
            c.append(j)
            j = p[j]
        out.append(c)
    return out


def lcm(a, b):
    return a // gcd(a, b) * b


def order(p):
    z = 1
    for c in cycles(p):
        z = lcm(z, len(c))
    return z


def key_word_perm():
    # Image word y_t receives a source word and a nibble permutation:
    # y0=f(x2), y1=g(x5), y2=f(x1), y3=g(x0),
    # y4=f(x3), y5=g(x6), y6=f(x7), y7=g(x4).
    sources = [2, 5, 1, 0, 3, 6, 7, 4]
    perms = [F, G, F, G, F, G, F, G]
    p = [0] * 256
    for dst_word, (src_word, q) in enumerate(zip(sources, perms)):
        for dst_nibble in range(32):
            p[32 * dst_word + dst_nibble] = 32 * src_word + q[dst_nibble]
    return p


def update_nibbles(state, rc):
    """Apply one key update to a list of 256 nibble values."""
    p = key_word_perm()
    out = [state[p[dst]] for dst in range(256)]
    for j in range(8):
        out[64 + F[j]] ^= (rc >> (4 * j)) & 15
    return out


def rank_gf2(vectors):
    basis = {}
    for v in vectors:
        while v:
            b = v.bit_length() - 1
            if b in basis:
                v ^= basis[b]
            else:
                basis[b] = v
                break
    return len(basis)


ddt = Counter()
for a in range(16):
    for x in range(16):
        d = S[x] ^ S[x ^ a]
        ddt[a, d] += 1
one_transitions = [(a, d) for (a, d), count in ddt.items() if a and count == 16]

print("S cycles", cycles(S))
print("S DDT max", max(ddt.values()), "one-transitions", one_transitions)
print("S fixed points", [x for x in range(16) if S[x] == x])
print("F cycles", cycles(F))
print("G cycles", cycles(G))
print("order(F), order(G)", order(F), order(G))

K = key_word_perm()
kc = cycles(K)
print("K length/order", len(K), order(K))
print("K cycles", kc)

rcs = [0x988CC9DD, 0xF0E4A1B5, 0x21357064, 0x8397D2C6,
       0xC7D39682, 0x4F5B1E0A, 0x5E4A0F1B, 0x7C682D39,
       0x392D687C, 0xB3A7E2F6, 0xA7B3F6E2, 0x8E9ADFCB]

# If RC enters word K2 as an integer XOR, only its low eight nibbles matter.
# Orbit those positions under the nibble permutation and print the smallest
# cycle periods represented.
rc_positions = set(range(64, 72))
rc_orbit = set()
for x in rc_positions:
    for t in range(order(K)):
        rc_orbit.add(x)
        x = K[x]
print("RC low-nibble orbit size", len(rc_orbit), sorted(rc_orbit))
print("RC orbit cycle lengths",
      sorted(len(c) for c in kc if set(c) & rc_positions))

# Round constants seen by each key component over 12 updates. This proves they
# are nonzero and not periodic within the documented 12 steps.
printed = []
for r in range(12):
    printed.append(rcs[r])
print("RC distinct/nonzero", len(set(printed)), all(printed), rcs)

# The update is an invertible nibble permutation before the constant XOR. If
# RC enters as a zero-extended integer in K2, its eight affected nibbles are
# mapped by F.
for i, rc in enumerate(rcs, 1):
    const = {64 + F[j]: (rc >> (4 * j)) & 15 for j in range(8)}
    bad_cycles = []
    for c in kc:
        parity = 0
        for position in c:
            parity ^= const.get(position, 0)
        if parity:
            bad_cycles.append((len(c), parity))
    total_rc_nibble_xor = 0
    for j in range(8):
        total_rc_nibble_xor ^= (rc >> (4 * j)) & 15
    print(
        f"RC {i:2d}: nibble-xor={total_rc_nibble_xor:x}, "
        f"P(K)+K=RC impossible on cycles={bad_cycles}"
    )

# The linear functionals invariant under the nibble permutation P are the
# cycle-XOR functionals: one scalar bit for each (P-cycle, bit position). Count
# those that also annihilate each RC image.
functional_rows = []
for i, rc in enumerate(rcs, 1):
    const = {64 + F[j]: (rc >> (4 * j)) & 15 for j in range(8)}
    row = 0
    k = 0
    for c in kc:
        for bit in range(4):
            parity = sum((const.get(p, 0) >> bit) & 1 for p in c) & 1
            if parity:
                row |= 1 << k
            k += 1
    functional_rows.append(row)
print(
    "affine-invariant scalar bits",
    16 - rank_gf2(functional_rows),
    "constraint rows",
    [hex(r) for r in functional_rows],
)

# Prefix-periodic master-key classes: T_s o ... o T_1(K)=K. For an affine
# permutation with linear part Q=P^s, a Q-cycle is solvable exactly when the
# accumulated constant XORs to zero around that cycle; it then contributes one
# free nibble. This computes only fixed classes of a schedule prefix, not
# equivalent encryption keys.
for s in range(1, 13):
    q = list(range(256))
    constant = [0] * 256
    for rc in rcs[:s]:
        constant = update_nibbles(constant, rc)
        q = [K[q[i]] for i in range(256)]
    fixed_cycles = []
    impossible_cycles = []
    for c in cycles(q):
        parity = 0
        for i in c:
            parity ^= constant[i]
        (fixed_cycles if parity == 0 else impossible_cycles).append(
            (len(c), parity)
        )
    print(
        f"prefix {s:2d}: fixed cycles={len(fixed_cycles)}, "
        f"log2(fixed master keys)="
        f"{4 * len(fixed_cycles) if not impossible_cycles else 'none'}, "
        f"impossible cycles={len(impossible_cycles)}"
    )
