"""Finite check for the AXIS uniform-state reachability obstruction."""

from axis_model import INIT_REGS


def top_triple(j, t):
    return [
        (INIT_REGS[j] >> ((189 + t + k) % 192)) & 1
        for k in range(3)
    ]


uniform = {
    j: {t for t in range(192) if len(set(top_triple(j, t))) == 1}
    for j in range(8)
}

assert uniform[2] & uniform[3] == {27, 34, 35, 49, 70, 141, 187, 188}
for t in (27, 34, 35, 49, 70, 141, 187, 188):
    assert len(set(top_triple(4, t))) > 1

for t in range(192):
    assert any(len(set(top_triple(j, t))) > 1 for j in (2, 3, 4))

print("192 residues checked; no uniform target is reachable")
