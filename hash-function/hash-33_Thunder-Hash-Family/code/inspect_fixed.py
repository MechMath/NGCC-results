#!/usr/bin/env python3
"""Inspect the fixed space of the pinned Thunder-p linear layer."""

from pathlib import Path
import importlib.util
import sys

SCRIPT = Path("/home/mmat/mmat-preview/campaigns/rebuild-20261119/runs/rebuild-117-hash-33-ds02/run/slots/6257a49202594dff/thunder.py")
spec = importlib.util.spec_from_file_location("thunder", SCRIPT)
t = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = t
spec.loader.exec_module(t)


def basis_image(apply, dim):
    cols = []
    for i in range(dim):
        lanes = [0] * 25
        lanes[i // 64] = 1 << (i % 64)
        y = apply(t.state_from_lanes(lanes))
        cols.append(t.lanes_to_state_int(y))
    return cols


def add_basis(basis, x):
    x = x
    piv = {b.bit_length() - 1: b for b in basis}
    while x:
        p = x.bit_length() - 1
        if p not in piv:
            piv[p] = x
            return sorted(piv.values(), reverse=True), True
        x ^= piv[p]
    return sorted(piv.values(), reverse=True), False


cols = basis_image(lambda state: state, 1600)
cols = [t.lanes_to_state_int(t.rho(t.state_int_to_lanes(x))) for x in cols]
cols = [t.lanes_to_state_int(t.theta(t.state_int_to_lanes(x))) for x in cols]
cols = [t.lanes_to_state_int(t.pi(t.state_int_to_lanes(x))) for x in cols]

# Solve (L+I)v=0 with row reduction of columns represented as equations.
rows = cols[:]
for i, c in enumerate(rows):
    rows[i] ^= 1 << i

pivots = {}
for row in rows:
    while row:
        p = row.bit_length() - 1
        if p in pivots:
            row ^= pivots[p]
        else:
            pivots[p] = row
            break
print("rank(L+I)", len(pivots))
free = [j for j in range(1600) if j not in pivots]
print("nullity", len(free))
for j in free:
    x = 1 << j
    changed = True
    while changed:
        changed = False
        for p, row in pivots.items():
            if (x >> p) & 1:
                x ^= row
                changed = True
    lanes = [(x >> (64*i)) & t.MASK64 for i in range(25)]
    print("v", hex(x))
    print(" nonzero lanes", [i for i,v in enumerate(lanes) if v])
    print(" lane patterns", [(i,hex(v)) for i,v in enumerate(lanes) if v])
