#!/usr/bin/env python3
"""Refute arbitrary invariants of cycle-count sums grouped by cycle length mod 8."""

from itertools import product

from thunder_cycle_invariants import CYCLE_OF
from thunder_fixedspace import RC, linear, pos


# C1,C2 have length 10; C3,C4 have length 5; C0,C5 are singleton cycles.
LENGTH_GROUPS = ((1, 2), (3, 4), (0, 5))


def group_count_mod8(x):
    """Return (large10, medium5, singleton) counts modulo eight."""
    counts = [0, 0, 0]
    for a in range(5):
        for z in range(64):
            value = sum(((x >> pos(a, y, z)) & 1) << y for y in range(5))
            cycle = CYCLE_OF[value]
            if cycle in LENGTH_GROUPS[0]:
                counts[0] += 1
            elif cycle in LENGTH_GROUPS[1]:
                counts[1] += 1
            else:
                counts[2] += 1
    return tuple(count & 7 for count in counts)


def possible_signatures():
    """Exact constraints: three nonnegative group counts summing to 320."""
    return {
        (large, medium, singleton)
        for large, medium, singleton in product(range(8), repeat=3)
        if (large + medium + singleton) % 8 == 0
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


def build_connected_round_graph(rnd, limit=20000):
    target = possible_signatures()
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
    seed = 0xA5A5A5A5DEADBEEF ^ (0x9E3779B97F4A7C15 * (rnd + 1))
    while checked < limit:
        x = deterministic_x(seed)
        seed = (seed + 0xD1B54A32D192ED03) & ((1 << 64) - 1)
        a = group_count_mod8(x)
        b = group_count_mod8(linear(x ^ RC[rnd]))
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
    target = possible_signatures()
    print("possible_signatures", len(target))
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
            aa = group_count_mod8(x)
            bb = group_count_mod8(linear(x ^ RC[rnd]))
            assert {aa, bb} == {a, b} and aa != bb
            print("  edge", a, b, "witness", f"{x:0400x}")


if __name__ == "__main__":
    main()
