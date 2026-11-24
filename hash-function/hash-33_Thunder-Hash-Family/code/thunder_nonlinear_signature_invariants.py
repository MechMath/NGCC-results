#!/usr/bin/env python3
"""Refute arbitrary nonlinear functions of coupled S-box cycle-count parities."""

from thunder_cycle_invariants import CYCLE_OF, signature
from thunder_fixedspace import RC, linear, pos, psi


def cycle_parity(x):
    """Six parity bits, one for each S-box permutation cycle.

    This is the same map as thunder_cycle_invariants.signature, repeated here
    to keep the object used by the certificate explicit.
    """
    out = 0
    for a in range(5):
        for z in range(64):
            value = sum(((x >> pos(a, y, z)) & 1) << y for y in range(5))
            out ^= 1 << CYCLE_OF[value]
    return out


def build_connected_round_graph(rnd, limit=20000):
    """Find a deterministic witness for a spanning tree of signature pairs."""
    vertices = set()
    edges = {}
    frontier = []
    checked = 0

    # A small deterministic xorshift PRNG makes the finite certificate
    # reproducible without relying on CPython's random-stream implementation.
    state = (0x9E3779B97F4A7C15 ^ (rnd + 1) ^ (0xD1B54A32D192ED03 * (rnd + 1))) & (
        (1 << 64) - 1
    )

    def next_word():
        nonlocal state
        state ^= state << 13
        state &= (1 << 64) - 1
        state ^= state >> 7
        state ^= state << 17
        state &= (1 << 64) - 1
        return state

    while checked < limit:
        x = 0
        for _ in range(25):
            x = (x << 64) | next_word()
        a = cycle_parity(x)
        b = cycle_parity(linear(x ^ RC[rnd]))
        vertices.add(a)
        vertices.add(b)
        checked += 1

        key = (min(a, b), max(a, b))
        if a != b and key not in edges:
            edges[key] = x
            frontier.append(key)

        # Stop only after all 32 even-weight signatures have occurred and the
        # observed graph on those signatures is connected.
        if len(vertices) == 32:
            parent = {v: v for v in vertices}

            def find(v):
                while parent[v] != v:
                    parent[v] = parent[parent[v]]
                    v = parent[v]
                return v

            for u, v in frontier:
                ru, rv = find(u), find(v)
                if ru != rv:
                    parent[ru] = rv
            if len({find(v) for v in vertices}) == 1:
                return checked, edges, frontier

    raise RuntimeError(
        f"round {rnd}: graph not connected after {checked} deterministic witnesses"
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
    for rnd in range(12):
        checked, edges, _ = build_connected_round_graph(rnd)
        vertices = {v for edge in edges for v in edge}
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
            assert cycle_parity(x) in (a, b)
            assert cycle_parity(linear(x ^ RC[rnd])) in (a, b)
            assert cycle_parity(x) != cycle_parity(linear(x ^ RC[rnd]))
            print(
                "  edge",
                f"{a:02x}-{b:02x}",
                "witness",
                f"{x:0400x}",
                "images",
                f"{cycle_parity(x):02x}",
                f"{cycle_parity(linear(x ^ RC[rnd])):02x}",
            )

        # Consistency check: the round itself supplies the same edge after psi,
        # because psi preserves the cycle label of every local S-box input.
        x = edges[tree[0]]
        assert cycle_parity(psi(x)) == cycle_parity(x)


if __name__ == "__main__":
    main()
