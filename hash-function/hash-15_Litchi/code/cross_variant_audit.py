#!/usr/bin/env python3
"""Exact checks for Litchi cross-variant IV and padding separation.

This is a proof aid, not execution evidence for a security claim.  Bit strings
follow the specification's 1600-bit, most-significant-bit-first convention.
"""

CONFIGS = {
    "Litchi-512": (576, 0, 512),
    "Litchi-768": (832, 0, 768),
    "Litchi-1024": (1088, 0, 1024),
    "Litchi-XOF": (1024, 1, None),
}


def iv1600(capacity: int, fid: int) -> int:
    assert 0 <= capacity < 2**63
    assert fid in (0, 1)
    return (fid << 63) + capacity


def bits(value: int, width: int) -> str:
    assert 0 <= value < 2**width
    return format(value, f"0{width}b")


def pad_bits(message: str, rate: int) -> str:
    """Specification padding: M || 1 || 0^(r-1-(|M| mod r))."""
    zeros = rate - 1 - (len(message) % rate)
    return message + "1" + "0" * zeros


def main() -> None:
    ivs = {name: iv1600(c, fid) for name, (c, fid, _) in CONFIGS.items()}
    assert len(set(ivs.values())) == len(ivs)
    for name, value in ivs.items():
        assert len(bits(value, 1600)) == 1600
        print(f"{name:12s} V={value}  hex={value:0400x}")

    # At length 512 the two padded strings agree, but their block parses do not.
    message = "0" * 512
    p512 = pad_bits(message, 1024)   # Litchi-512: c=576, r=1024.
    p1024 = pad_bits(message, 512)   # Litchi-1024: c=1088, r=512.
    assert p512 == p1024 == message + "1" + "0" * 511
    assert len(p512) == 1024
    assert len(p512) // 1024 == 1
    assert len(p1024) // 512 == 2
    print("common padded length:", len(p512))
    print("Litchi-512 block count:", len(p512) // 1024)
    print("Litchi-1024 block count:", len(p1024) // 512)

    # Equal-length IV strings cannot be proper prefixes.  This is only tag
    # injectivity; the arbitrary-permutation mapping below shows why it is not
    # an output-separation theorem.
    for left in ivs:
        for right in ivs:
            if left != right:
                assert not bits(ivs[left], 1600).startswith(bits(ivs[right], 1600))

    # Empty-message squeeze inputs are 2^1599 + V because the sole padded
    # block is 1||0^(r-1).
    squeeze_inputs = {name: (1 << 1599) + val for name, val in ivs.items()}
    assert len(set(squeeze_inputs.values())) == len(ivs)

    # A deliberately programmed permutation Q (not Litchi's specified P).
    # Set LSB_c(Q(ST))=j*2^c+V; then Q(ST) xor ST has c low zero bits.
    programmed = {}
    for j, (name, (c, fid, _)) in enumerate(CONFIGS.items(), 1):
        programmed[name] = (j << c) + ivs[name]
    assert len(set(programmed.values())) == len(programmed)
    assert not (set(squeeze_inputs.values()) & set(programmed.values()))
    for name, (c, _, _) in CONFIGS.items():
        out_c = programmed[name] ^ squeeze_inputs[name]
        assert out_c & ((1 << c) - 1) == 0
        print(f"{name:12s} programmed Q(ST)={programmed[name]:0400x}")

    print("PASS: IVs distinct; 512-bit padding collision is parse-only; "
          "programmed permutation gives equal zero 512-bit prefixes.")


if __name__ == "__main__":
    main()
