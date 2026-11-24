#!/usr/bin/env python3
"""Exact GF(2) analysis of CHIME's lambda layer.

This is an exploration aid.  The submitted proof will give the kernel relation
explicitly and will not depend on this script as evidence.
"""

NAMES = ("A0", "A1", "B0", "B1", "C0", "C1")
OFFSETS = {name: 256 * index for index, name in enumerate(NAMES)}
MASK = (1 << 256) - 1


def _xor_all(values):
    result = 0
    for value in values:
        result ^= value
    return result


def _permutation_map(block_size, pairs):
    result = {}
    for old_block, new_block in pairs:
        for bit in range(block_size):
            result[old_block * block_size + bit] = new_block * block_size + bit
    return result


PERM32 = _permutation_map(
    32, ((0, 1), (1, 2), (2, 3), (3, 0), (4, 5), (5, 6), (6, 7), (7, 4))
)
PERM64 = _permutation_map(64, ((0, 1), (1, 2), (2, 3), (3, 0)))
SWAP64 = _permutation_map(64, ((0, 1), (1, 0), (2, 3), (3, 2)))
SWAP128 = _permutation_map(128, ((0, 1), (1, 0)))


def _value(state, slot):
    if isinstance(state, dict):
        return state[slot]
    return ((state >> OFFSETS[slot]) & MASK) << OFFSETS[slot]


def _apply_map(local, mapping):
    result = 0
    while local:
        bit = local & -local
        position = bit.bit_length() - 1
        local -= bit
        if position in mapping:
            result |= 1 << mapping[position]
    return result


def _mapped(state, source, target, mapping):
    local = (_value(state, source) >> OFFSETS[source]) & MASK
    return _apply_map(local, mapping) << OFFSETS[target]


def _shifted(state, source, target, amount, right=False):
    local = (_value(state, source) >> OFFSETS[source]) & MASK
    result = 0
    while local:
        bit = local & -local
        position = bit.bit_length() - 1
        local -= bit
        word, within = divmod(position, 64)
        new_within = within + amount if right else within - amount
        if 0 <= new_within < 64:
            result |= 1 << (64 * word + new_within)
    return result << OFFSETS[target]


def _rotated(state, source, target, amount):
    local = (_value(state, source) >> OFFSETS[source]) & MASK
    result = 0
    while local:
        bit = local & -local
        position = bit.bit_length() - 1
        local -= bit
        word, within = divmod(position, 64)
        result |= 1 << (64 * word + ((within + amount) % 64))
    return result << OFFSETS[target]


def lam(state):
    d = {name: _value(state, name) for name in NAMES}
    d["B1"] ^= _mapped(state, "C1", "B1", PERM32)
    d["B0"] ^= d["A1"]
    d["C0"] ^= _rotated(state, "A0", "C0", 29)
    d["B1"] ^= _rotated(state, "A1", "B1", 31)
    d["C1"] ^= _rotated(state, "A0", "C1", 13)
    d["C0"] ^= d["B1"]
    d["A0"] = _mapped(state, "A0", "A0", PERM64)
    d["C1"] ^= _mapped(d, "B1", "C1", PERM32)
    d["A1"] = _mapped(state, "A1", "A1", SWAP128)
    d["A0"] ^= _mapped(d, "C0", "A0", SWAP64)
    d["A1"] ^= _mapped(d, "B0", "A1", PERM32)
    d["B1"] ^= _shifted(d, "A0", "B1", 7)
    d["C1"] ^= _shifted(d, "A1", "C1", 5, right=True)
    return _xor_all(d.values())


def tau(round_index, state):
    """Apply tau using the table on page 7 of the specification."""
    group = round_index // 3
    old_to_new = (
        {
            "C1": "A0",
            "C0": "C1",
            "B1": "C0",
            "B0": "B1",
            "A1": "B0",
            "A0": "A1",
        }
        if group % 2 == 0
        else {
            "A0": "C1",
            "C1": "C0",
            "C0": "B1",
            "B1": "B0",
            "B0": "A1",
            "A1": "A0",
        }
    )
    result = 0
    for old, new in old_to_new.items():
        local = (_value(state, old) >> OFFSETS[old]) & MASK
        result |= local << OFFSETS[new]
    return result


def chi(round_index, state):
    """Apply chi to each of the two 3-bit lanes."""
    d = {
        name: (_value(state, name) >> OFFSETS[name]) & MASK
        for name in NAMES
    }
    out = {name: 0 for name in NAMES}
    lanes = (
        (("A0", "B0", "C0"), ("A1", "B1", "C1"))
        if round_index % 2 == 0
        else (("A0", "B0", "C0"), ("A1", "B1", "C1"))
    )
    if round_index % 2 == 0:
        for lane in lanes:
            a, b, c = lane
            out[a] = d[a] ^ ((~d[b]) & d[c] & MASK)
            out[b] = d[b] ^ ((~d[c]) & d[a] & MASK)
            out[c] = d[c] ^ ((~d[a]) & d[b] & MASK)
    else:
        # (A0,B1,C1) is one lane and (A1,B0,C0) the other.
        for a, b, c in (("A0", "B1", "C1"), ("A1", "B0", "C0")):
            out[a] = d[a] ^ ((~d[b]) & d[c] & MASK)
            out[b] = d[b] ^ ((~d[c]) & d[a] & MASK)
            out[c] = d[c] ^ ((~d[a]) & d[b] & MASK)
    # The formulas above are local to each slot; retain the slot addresses.
    return _xor_all(
        out[name] << OFFSETS[name]
        for name in NAMES
    )


def round_function(round_index, state):
    state = lam(state)
    constant = 0xDEADBEEF00000000 ^ round_index
    constant ^= (0x9E3779B97F4A7C15 * (round_index + 1)) & ((1 << 64) - 1)
    a0 = (
        (_value(state, "A0") >> OFFSETS["A0"]) & MASK
    ) ^ _xor_all(constant << (64 * word) for word in range(4))
    state = (state & ~(MASK << OFFSETS["A0"])) | (a0 << OFFSETS["A0"])
    return tau(round_index, chi(round_index, state))


def dependencies(indices):
    pivots = {}
    relations = []
    for index in indices:
        vector = lam(1 << index)
        provenance = 1 << index
        while vector:
            pivot = vector.bit_length() - 1
            if pivot in pivots:
                vector ^= pivots[pivot][0]
                provenance ^= pivots[pivot][1]
            else:
                pivots[pivot] = (vector, provenance)
                break
        if not vector:
            relations.append(provenance)
    return pivots, relations


def support(vector, width):
    return [
        (NAMES[index // 256], index % 256)
        for index in range(width)
        if (vector >> index) & 1
    ]


if __name__ == "__main__":
    for label, indices in (
        ("all", range(1536)),
        ("rate512", range(512)),
        ("rate448", range(448)),
        ("A0", range(256)),
        ("A1", range(256, 512)),
    ):
        pivots, relations = dependencies(indices)
        print(label, "rank", len(pivots), "nullity", len(relations))
        for relation in relations[:4]:
            print(" ", support(relation, 1536))
