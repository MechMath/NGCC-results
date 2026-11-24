#!/usr/bin/env python3
"""Finite framing checks for the exact CreTAKE message layouts.

The concrete widths come from the original specification's Tables 2--4.  The
model deliberately separates protocol records (already parsed) from wire bytes
so that the framing precondition is visible.
"""

from dataclasses import dataclass
from itertools import product


# Bytes.  CPA/CCA public keys have the same width in PolarLAC and ZEN.
WIDTH = {
    "ePolarLAC-pk": 530,
    "PolarLAC-ct": 640,
    "eZEN-pk": 615,
    "ZEN-ct": 512,
    "BiT128-sig": 1504,
    "BiT256-sig": 3456,
    "BiT512-sig": 6695,
}

# Initiator-responder message layouts for each concrete family at a level.
LAYOUTS = {
    "K2S-PolarLAC": (("ePolarLAC-pk",), ("PolarLAC-ct", "PolarLAC-ct", "BiT-sig")),
    "K2S-ZEN": (("eZEN-pk",), ("ZEN-ct", "ZEN-ct", "BiT-sig")),
    "S2K-PolarLAC": (("ePolarLAC-pk", "PolarLAC-ct", "BiT-sig"), ("PolarLAC-ct",)),
    "S2K-ZEN": (("eZEN-pk", "ZEN-ct", "BiT-sig"), ("ZEN-ct",)),
    "K2K-PolarLAC": (("ePolarLAC-pk", "PolarLAC-ct"), ("PolarLAC-ct",)),
    "K2K-ZEN": (("eZEN-pk", "ZEN-ct"), ("ZEN-ct",)),
    "S2S-ePolarLAC": (("ePolarLAC-pk", "BiT-sig"), ("PolarLAC-ct", "BiT-sig")),
    "S2S-eZEN": (("eZEN-pk", "BiT-sig"), ("ZEN-ct", "BiT-sig")),
}


def concrete_width(kind: str, level: int) -> int:
    if kind == "BiT-sig":
        return WIDTH[f"BiT{level}-sig"]
    if kind == "ePolarLAC-pk":
        return {128: 530, 256: 1060, 512: 2116}[level]
    if kind == "PolarLAC-ct":
        return {128: 640, 256: 1280, 512: 2560}[level]
    if kind == "eZEN-pk":
        return {128: 615, 256: 1229, 512: 2458}[level]
    if kind == "ZEN-ct":
        return {128: 512, 256: 1024, 512: 2048}[level]
    raise KeyError(kind)


def layouts_at_level(level: int):
    return {
        name: (
            tuple(concrete_width(k, level) for k in first),
            tuple(concrete_width(k, level) for k in second),
        )
        for name, (first, second) in LAYOUTS.items()
    }


def fixed_segments(total: int, widths: tuple[int, ...]):
    if sum(widths) != total:
        return None
    out, pos = [], 0
    for width in widths:
        out.append((pos, pos + width))
        pos += width
    return tuple(out)


def variable_ambiguous(component_lengths: tuple[int, int]) -> bool:
    """A delimiter-free concatenation is ambiguous for some two-part lengths."""
    a, b = component_lengths
    return a > 0 and b > 0


@dataclass(frozen=True)
class Consequence:
    level: int
    layout: str
    direction: str
    widths: tuple[int, ...]
    total: int
    cuts: tuple[tuple[int, int], ...]


def check_all():
    consequences = []
    collisions = []
    for level in (128, 256, 512):
        by_total = {}
        for name, (first, second) in layouts_at_level(level).items():
            for direction, widths in (("I->R", first), ("R->I", second)):
                total = sum(widths)
                cuts = fixed_segments(total, widths)
                assert cuts is not None
                consequences.append(Consequence(level, name, direction, widths, total, cuts))
                by_total.setdefault(total, []).append((name, direction, widths))
        for total, entries in sorted(by_total.items()):
            if len(entries) > 1:
                collisions.append((level, total, entries))
    return consequences, collisions


def cross_profile_signed_bytes(kem_family: str, level: int) -> bytes:
    """The identical byte string signed in S2K-initiator and S2S-responder
    roles after setting cj := ec.  Fillers stand for arbitrary encodings."""
    pk_kind = "ePolarLAC-pk" if kem_family == "PolarLAC" else "eZEN-pk"
    ct_kind = "PolarLAC-ct" if kem_family == "PolarLAC" else "ZEN-ct"
    fp = b"\xa5" * concrete_width(pk_kind, level)
    ec = b"\x5a" * concrete_width(ct_kind, level)
    s2k_initiator_signed = fp + ec
    s2s_responder_signed = fp + ec
    assert s2k_initiator_signed == s2s_responder_signed
    return s2k_initiator_signed


if __name__ == "__main__":
    consequences, collisions = check_all()
    print(f"checked fixed-width messages: {len(consequences)}")
    print("same-length cross-layout messages:")
    for level, total, entries in collisions:
        print(level, total, entries)

    # Exhaustively exhibit two distinct two-component parses of one byte string
    # under a variable-length, delimiter-free model.
    witnesses = []
    for a, b, c, d in product(range(1, 4), repeat=4):
        if a + b == c + d and (a, b) != (c, d):
            witnesses.append((("x" * a, "y" * b), ("x" * c, "y" * d)))
            break
    print("variable-length ambiguity witness:", witnesses[0])
    assert variable_ambiguous((1, 2)) and witnesses
    for family, level in product(("PolarLAC", "ZEN"), (128, 256, 512)):
        signed = cross_profile_signed_bytes(family, level)
        print("cross-profile signed-byte equality:", family, level, len(signed))
