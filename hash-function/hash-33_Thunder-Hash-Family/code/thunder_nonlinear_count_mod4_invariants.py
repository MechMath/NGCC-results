#!/usr/bin/env python3
"""Search all coupled S-box cycle-count invariants modulo four."""

from thunder_cycle_invariants import CYCLE_OF
from thunder_fixedspace import RC, linear, pos


def count_mod4(x):
    """Pack six independent cycle-count residues mod four into twelve bits.

    Counts sum to 320, hence 0 mod 4 on every input. Two bits per cycle are
    packed as c0::2, c1::2, ..., c5::2.
    """
    counts = [0] * 6
    for a in range(5):
        for z in range(64):
            value = sum(((x >> pos(a, y, z)) & 1) << y for y in range(5))
            counts[CYCLE_OF[value]] += 1
    out = 0
    for j, count in enumerate(counts):
        out |= (count & 3) << (2 * j)
    return out


def count_mod4_from_counts(counts):
    out = 0
    for j, count in enumerate(counts):
        out |= (count & 3) << (2 * j)
    return out


def attainable_mod4():
    """The six residues in [0,3] whose sum is 320 mod four."""
    from itertools import product

    return {
        count_mod4_from_counts(counts)
        for counts in product(range(4), repeat=6)
        if sum(counts) % 4 == 0
    }


def deterministic_x(seed):
    state = seed & ((1 << 64) - 1)
    out = 0
    for _ in range(25):
        state ^= state << 13
        state &= (1 << 64) - 1
        state ^= state >> 7
        state ^= state << 17
        state &= (1 << 64) - 1
        out = (out << 64) | state
    return out


def build_connected_round_graph(rnd, limit=30000):
    target = attainable_mod4()
    parent = {v: v for v in target}

    def find(v):
        while parent[v] != v:
            parent[v] = parent[parent[v]]
            v = parent[v]
        return v

    def union(u, v):
        ru, rv = find(u), find(v)
        if ru == rv:
            return False
        parent[ru] = rv
        return True

    vertices = set()
    edges = {}
    components = len(target)
    checked = 0
    seed = 0x123456789ABCDEF ^ (0x9E3779B97F4A7C15 * (rnd + 1))
    while checked < limit:
        x = deterministic_x(seed)
        seed = (seed + 0xD1B54A32D192ED03) & ((1 << 64) - 1)
        a = count_mod4(x)
        b = count_mod4(linear(x ^ RC[rnd]))
        assert a in target and b in target
        vertices.update((a, b))
        checked += 1
        if a != b and (min(a, b), max(a, b)) not in edges:
            edges[(min(a, b), max(a, b))] = x
            if union(a, b):
                components -= 1
        if len(vertices) == len(target) and components == 1:
            return checked, target, edges
    raise RuntimeError(
        f"round {rnd}: checked={checked}, vertices={len(vertices)}/{len(target)}, "
        f"components={components}"
    )


def spanning_tree(vertices, edges):
    parent = {v: v for v in vertices}
    tree = []

    def find(v):
        while parent[v] != v:
            parent[v] = parent[parent[v]]
            v = parent[v]
        return v

    for key in sorted(edges):
        u, v = key
        ru, rv = find(u), find(v)
        if ru != rv:
            parent[ru] = rv
            tree.append(key)
    return tree


def main():
    target = attainable_mod4()
    print("attainable_signatures", len(target))
    for rnd in range(12):
        checked, vertices, edges = build_connected_round_graph(rnd)
        tree = spanning_tree(vertices, edges)
        print(
            "round",
            rnd,
            "checked",
            checked,
            "vertices",
            len(vertices),
            "edges",
            len(edges),
            "spanning_tree_edges",
            len(tree),
        )
        for a, b in tree:
            x = edges[(a, b)]
            aa = count_mod4(x)
            bb = count_mod4(linear(x ^ RC[rnd]))
            assert {aa, bb} == {a, b} and aa != bb
            print("  edge", f"{a:03x}-{b:03x}", "witness", f"{x:0400x}")


if __name__ == "__main__":
    main()
