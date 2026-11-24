#!/usr/bin/env python3
"""Exact finite search for mixed per-S-box affine-plane encounters.

This models the direction condition for a 640-dimensional product of affine
planes on one Thunder-p round and the next S-box projections.  It is a scratch
search, not execution evidence.
"""

from __future__ import annotations

from itertools import combinations, product
from pathlib import Path
import importlib.util
import sys

from pysat.solvers import Cadical195, Glucose3


THUNDER_PATH = Path(
    "/home/mmat/mmat-preview/campaigns/rebuild-20261119/"
    "runs/rebuild-117-hash-33-ds02/run/slots/"
    "6257a49202594dff/thunder.py"
)

spec = importlib.util.spec_from_file_location("thunder", THUNDER_PATH)
t = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = t
spec.loader.exec_module(t)


def psi_word(x: int) -> int:
    return sum(v << y for y, v in enumerate(t._psi_word(tuple((x >> y) & 1 for y in range(5)))))


def all_affine_linear_slices() -> list[tuple[tuple[int, ...], tuple[int, ...], tuple[int, int]]]:
    """Return (elements, output elements, two direction vectors)."""
    result = []
    for vertices in combinations(range(32), 4):
        outs = tuple(psi_word(x) for x in vertices)
        if outs[0] ^ outs[1] ^ outs[2] ^ outs[3]:
            continue
        base = vertices[0]
        nonzero_differences = tuple(sorted(x ^ base for x in vertices[1:]))
        directions = nonzero_differences[:2]
        u, v = directions
        if {base, base ^ u, base ^ v, base ^ u ^ v} != set(vertices):
            continue
        result.append((vertices, outs, (directions[0], directions[1])))
    assert len(result) == 120
    return result


def index(x: int, y: int, z: int) -> int:
    return 64 * (5 * y + x) + z


def local_from_state(value: int, x: int, z: int) -> int:
    return sum(((value >> index(x, y, z)) & 1) << y for y in range(5))


def apply_l(value: int) -> int:
    state = t.rho(t.state_int_to_lanes(value))
    # Literal pinned theta.  In particular, row 0 of Q has t_0=41; the
    # scratch thunder.py omits this rotation.
    p = [0] * 5
    q = [0] * 5
    ty = (41, 50, 6, 10, 27)
    for x in range(5):
        p[x] = state[x][0] ^ state[x][1] ^ state[x][2] ^ state[x][3] ^ state[x][4]
        q[x] = (
            t.rotr64(state[x][0], ty[0])
            ^ t.rotr64(state[x][1], ty[1])
            ^ t.rotr64(state[x][2], ty[2])
            ^ t.rotr64(state[x][3], ty[3])
            ^ t.rotr64(state[x][4], ty[4])
        )
    e = [p[x] ^ t.rotr64(p[(x - 1) % 5], 1) for x in range(5)]
    f = [q[(x + 1) % 5] ^ t.rotr64(q[(x - 2) % 5], 36) for x in range(5)]
    out = tuple(
        tuple(
            state[x][y]
            ^ t.rotr64(e[x], 26)
            ^ t.rotr64(f[x], (26 + ty[y]) % 64)
            for y in range(5)
        )
        for x in range(5)
    )
    return t.lanes_to_state_int(t.pi(out))


def main() -> None:
    local_planes = all_affine_linear_slices()
    sources = [(x, z) for x in range(5) for z in range(64)]
    assert len(sources) == 320

    # L(unit source bit), used to obtain every 5-by-5 local projection.
    l_images: dict[tuple[int, int, int], int] = {}
    for x, z in sources:
        for y in range(5):
            value = 1 << index(x, y, z)
            l_images[x, y, z] = apply_l(value)

    projections = []
    for x, z in sources:
        row = []
        for _, outputs, _ in local_planes:
            row.append(
                (
                    outputs[1] ^ outputs[0],
                    outputs[2] ^ outputs[0],
                )
            )
        projections.append(row)

    # A common output direction plane H_d must contain each source contribution.
    h_plane_set = set()
    for vertices in combinations(range(32), 4):
        directions = tuple(sorted(v ^ vertices[0] for v in vertices[1:]))
        if len({0, *directions}) == 4 and all(
            (a ^ b) in {0, *directions} for a in directions for b in directions
        ):
            h_plane_set.add(directions)
    h_planes = sorted(h_plane_set)
    assert len(h_planes) == 155

    # p(j,a): source j chooses local affine plane a.
    # h(d,b): destination d's common 2-dimensional direction plane is b.
    pvar = {
        (j, a): 1 + j * 120 + a
        for j in range(320)
        for a in range(120)
    }
    hbase = 1 + 320 * 120
    hvar = {
        (d, b): hbase + d * 155 + b
        for d in range(320)
        for b in range(155)
    }
    sbase = hbase + 320 * 155
    svar = {
        (d, b): sbase + d * 154 + b
        for d in range(320)
        for b in range(154)
    }
    clauses: list[list[int]] = []

    def add_clause(clause: list[int]) -> None:
        clauses.append(clause)

    for j in range(320):
        add_clause([pvar[j, a] for a in range(120)])

    for d in range(320):
        dx, dz = sources[d]
        # Images of the five local input bits in this destination slice.
        maps = {}
        for x, z in sources:
            maps[x, z] = [
                local_from_state(l_images[x, y, z], dx, dz) for y in range(5)
            ]

        def map_direction(source: tuple[int, int], direction: int) -> int:
            image = 0
            units = maps[source]
            for y in range(5):
                if (direction >> y) & 1:
                    image ^= units[y]
            return image

        for j in range(320):
            for p in range(120):
                u0, v0 = projections[j][p]
                u = map_direction(sources[j], u0)
                v = map_direction(sources[j], v0)
                nonzero = {u, v, u ^ v} - {0}
                if len(nonzero) == 2:
                    # The contribution is a 2-plane, forcing the common H.
                    direction = tuple(sorted(nonzero))
                    h = h_planes.index(direction)
                    add_clause([-pvar[j, p], hvar[d, h]])
                elif len(nonzero) == 1:
                    line = next(iter(nonzero))
                    allowed = [
                        hvar[d, h]
                        for h, hd in enumerate(h_planes)
                        if line in hd
                    ]
                    add_clause([-pvar[j, p], *allowed])
                # A rank-zero contribution imposes no condition.

        # Sequential at-most-one encoding for the common direction plane.
        add_clause([-hvar[d, 0], svar[d, 0]])
        for b in range(1, 154):
            add_clause([-hvar[d, b], svar[d, b]])
            add_clause([-svar[d, b - 1], svar[d, b]])
            add_clause([-hvar[d, b], -svar[d, b - 1]])
        add_clause([-hvar[d, 154], -svar[d, 153]])

    print(
        f"CNF: {len(pvar) + len(hvar) + len(svar)} variables, "
        f"{len(clauses)} clauses, {len(local_planes)} local planes, "
        f"{len(h_planes)} destination planes",
        flush=True,
    )
    print("solving direction CSP with CaDiCaL and Glucose3", flush=True)
    cadical = Cadical195(bootstrap_with=clauses)
    cadical_status = cadical.solve()
    print(f"CaDiCaL: {'SAT' if cadical_status else 'UNSAT'}", flush=True)
    glucose = Glucose3(bootstrap_with=clauses)
    glucose_status = glucose.solve()
    print(f"Glucose3: {'SAT' if glucose_status else 'UNSAT'}", flush=True)
    assert cadical_status == glucose_status
    if not cadical_status:
        return
    print("direction status: SAT", flush=True)
    model = {lit for lit in cadical.get_model() if lit > 0}
    selected = []
    for j in range(320):
        chosen = [a for a in range(120) if pvar[j, a] in model]
        # Any true choice among a satisfying assignment can be retained alone.
        selected.append(chosen[0])
    for j, p in enumerate(selected):
        print(sources[j], p, local_planes[p][0])

    # The solver selected the same local affine plane in every source slice.
    # Check the actual affine cosets (not only direction spaces) for all
    # consecutive round-constant boundaries.
    selected_plane = selected[0]
    assert all(p == selected_plane for p in selected)
    source_vertices, output_vertices, source_dirs = local_planes[selected_plane]
    output_base = min(output_vertices)
    output_dirs = (
        psi_word(source_dirs[0]) ^ psi_word(0),
        psi_word(source_dirs[1]) ^ psi_word(0),
    )

    round_constants = t.ROUND_CONSTANTS
    rc_images = {}
    for r, constant in enumerate(round_constants):
        rc_value = constant  # lane (x,y)=(0,0), z bits are the constant
        rc_images[r] = apply_l(rc_value)

    failures = []
    for dx, dz in sources:
        # All local output directions, projected to this destination slice.
        h_vectors = set()
        for x, z in sources:
            for direction in output_dirs:
                image = 0
                for y in range(5):
                    if (direction >> y) & 1:
                        image ^= l_images[x, y, z]
                h_vectors.add(local_from_state(image, dx, dz))
        h_vectors.discard(0)
        h_vectors.add(0)
        assert len(h_vectors) <= 4

        for r in range(len(round_constants) - 1):
            base = local_from_state(rc_images[r], dx, dz)
            projected = {base ^ h for h in h_vectors}
            values = sorted(projected)
            if len(values) not in (1, 2, 4):
                failures.append(((dx, dz), r, "not affine"))
                continue
            if len(values) == 4:
                v0 = values[0]
                outs = [psi_word(v) for v in values]
                if outs[0] ^ outs[1] ^ outs[2] ^ outs[3]:
                    failures.append(((dx, dz), r, values))
            # dimensions 0 and 1 are affine on every coset.

    print("coset failures:", len(failures), flush=True)
    for failure in failures[:20]:
        print(failure)


if __name__ == "__main__":
    main()
