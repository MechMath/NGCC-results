#!/usr/bin/env python3
"""Audit the one-block Appendix-B KAT feedforward arithmetic.

The specification prints each 64-bit word as an eight-byte little-endian
sequence.  This script keeps the appendix values as displayed, reverses them
to recover host-order words, applies the specified Davies-Meyer XOR, and
prints the result in the appendix's byte order.
"""

from __future__ import annotations


def words(text: str) -> list[int]:
    return [int(item, 16) for item in text.split()]


def display(value: int) -> int:
    return int.from_bytes(value.to_bytes(8, "little"), "big")


NORMATIVE_IV = words(
    """
    243f6a8885a308d3 13198a2e03707344 a4093822299f31d0 082efa98ec4e6c89
    452821e638d01377 be5466cf34e90c6c c0ac29b7c97c50dd 3d84d5b5b5470917
    9216d5d98979fb1b d1310ba698dfb5ac 2ffd72dbd01adfb7 b8e1afed6a267e96
    ba7c9045f12c7f99 24a19947b3916cf7 0801f2e2858efc16 636920d871574e69
    """
)

# Appendix B's "initial state of v" is the transpose of the matrix in
# Section 2.1 and uses 3f84 rather than normative IV_7=3d84.
APPENDIX_INITIAL_DISPLAY = words(
    """
    243f6a8885a308d3 452821e638d01377 9216d5d98979fb1b ba7c9045f12c7f99
    13198a2e03707344 be5466cf34e90c6c d1310ba698dfb5ac 24a19947b3916cf7
    a4093822299f31d0 c0ac29b7c97c50dd 2ffd72dbd01adfb7 0801f2e2858efc16
    082efa98ec4e6c89 3f84d5b5b5470917 b8e1afed6a267e96 636920d871574e69
    """
)

KAT = {
    1024: {
        "v20": words(
            """
            01ef1f6734470fd6 54350424e973d09b 4022f91f795af629 23c31b291c5bea5a
            e150b6244682d579 4354f396f9aab25a 456680cc69647723 3695e0f26a364bde
            81b7febe65d188c7 071c0ef0c6cade85 6717dded76fa7f8e 74635d0f5311a51e
            c9a27ffb2ebf7243 ef179a6f67184067 bac2196af3ffb86f e2afc6c6b20267c4
            """
        ),
        "digest": words(
            """
            0507e4b1ef75d025 dfa303ea0a8e2c47 f9c7c5503dc12be4 d38615f0b1e1ed2b
            0ec6527ec29778a4 36be43cd599500fd fe2718a07ba9ca85 c94271df47351109
            dc73a8ec672ba113 296b155e56052dd6 39a0e0a636afea48 88db3739e2f282cc
            da0d93dfbeefde73 902c89d42803b6cb 7944717688ebc3b2 ad2955c31ee6c681
            """
        ),
    },
    768: {
        "v20": words(
            """
            ff4e91e0df509d63 36ec27ce643c82ff d07c066f6d084190 a1c46500ce3faefc
            450d87b55f8ef52a ff352036c7870627 5666def8b9c55888 271f8bb73849ae92
            187bd64f6cda780c 4e49d17e1b6e7f77 b1188e9afa4196f8 26561c44123c76ba
            bcfa9a224cb720ba 544db3a6dfc420b4 09b08396c075ce7b 89349a50106f86b2
            """
        ),
        "digest": words(
            """
            b095f35a68fb71db bbf14c67e0adf525 407097444d3e7574 75c27122989feaa9
            5de65e6753a62500 4b0a6ef3f9466141 5508b9704ff7ca96 85a70e8d025e9b18
            1783a3e596036d8a dbcab183d8da789f 4f495b2a41fce59e 2c081a78a9b3b79e
            """
        ),
    },
    512: {
        "v20": words(
            """
            26cb47b9ea6b9765 7b2e214f3f542eb9 8cd7dfd0e4244355 84d4926a973e5b6e
            aa92c16124859399 bf706442eda3af03 2aaf6df838ca6578 00b9e5f871ba689b
            68761e997bc73e88 1dc987c3962787ab 1ec2998b9b0ab10e 30d250c269c3e3d8
            875e9dab5b93126e cbdf8ecf9bc74b02 1b6c109e0fc04edc ed1460b8fab2ce8c
            """
        ),
        "digest": words(
            """
            b69fc86f312df402 fd5d243c61ab3768 8572bbcdf2e7de28 e737707bf268fa8c
            ee80551c87e0baef 6fa34ad98d022401 a535b6f14f4403ea 8c61fdc44d303d3f
            """
        ),
    },
}


def main() -> None:
    for digest_bits, data in KAT.items():
        digest = data["digest"]
        v20 = data["v20"]
        computed = [
            display(iv ^ v) for iv, v in zip(NORMATIVE_IV, v20)
        ][: len(digest)]
        mismatches = [
            index
            for index, (actual, printed) in enumerate(zip(computed, digest))
            if actual != printed
        ]
        print(f"FEILIAN-{digest_bits}: mismatches={mismatches}")
        for index in mismatches:
            print(
                f"  index {index}: computed={computed[index]:016x} "
                f"appendix={digest[index]:016x}"
            )
            inferred_iv7 = display(digest[index]) ^ v20[7]
            print(f"  implied IV_7 from this digest word: {inferred_iv7:016x}")
        print(
            "  Appendix displayed initial word 13 (the transposed IV_7): "
            f"{APPENDIX_INITIAL_DISPLAY[13]:016x}"
        )
        print(f"  Normative IV_7: {NORMATIVE_IV[7]:016x}")


if __name__ == "__main__":
    main()
