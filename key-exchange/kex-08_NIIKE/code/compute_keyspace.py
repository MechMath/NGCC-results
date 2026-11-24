#!/usr/bin/env python3
"""Reproduce NIIKE modified-key-space counts from the pinned specification.

The factor lists below are transcribed literally from kex-08-spec.pdf,
Chapter 5.5, pages 36--38 (PDF page numbering).  For NGCC-I and NGCC-II,
repeated prime symbols in the display are represented as exponents.
"""

from fractions import Fraction
from pathlib import Path
import hashlib
import platform
import sys

import pymupdf
from sympy import factorint, sympify


PARAMETERS = {
    "NGCC-I": {
        "lambda": 128,
        "M_plus_hex": "24bed52b01b8d020e25aecd3b301b2fbf1d75d56d89d48d7b",
        "M_minus_hex": "3acebf3dd1f3042710750fce762eef",
        "M_plus_expression": (
            "3^4*5*7*11^2*19*23*29*31*41*43*47*53*71*79*83*89*"
            "97*107*109*113*131*137*149*151*157*163*167*181*229*239*269"
        ),
        "M_minus_expression": (
            "13*17*37*59*61*67*73*101*103*127*139*173*179*191*193*"
            "199*211*241"
        ),
    },
    "NGCC-II": {
        "lambda": 256,
        "M_plus_hex": (
            "111bfe3896341f28ceb842cd636de724dbafea02a82cd15fe14745256f4dd61"
            "770651044493edb23aa5084f997322f03"
        ),
        "M_minus_hex": (
            "c3d632025aa22b59429731bc4aec11b07edf774cda63d85acd5edf9"
        ),
        "M_plus_expression": (
            "3*7^3*11^2*13*17*19*23*31*37*47*53*59*73*83*97*101*103*107*113*"
            "127*131*137*139*149*151*163*167*179*181*191*223*227*229*233*"
            "239*257*263*269*281*307*311*313*317*337*347*367*373*379*383*"
            "461*593*787*937"
        ),
        "M_minus_expression": (
            "5*29*41*43*61*67*71*79*89*109*157*173*193*197*199*211*241*"
            "251*271*277*283*293*331*349*353*359*443*587*601*607"
        ),
    },
}


def parse_expression(expression):
    """Return (prime -> exponent) after proving the expression is a product."""
    value = sympify(expression)
    if not value.is_Integer:
        raise AssertionError(f"printed expression is not an integer: {expression}")
    factors = factorint(value)
    if not factors:
        raise AssertionError(f"failed to factor printed expression: {expression}")
    return {int(p): int(e) for p, e in factors.items()}


def extract_ngcc3_p(pdf_path):
    """Extract the displayed NGCC-III p using positioned monospace lines."""
    document = pymupdf.open(pdf_path)
    chunks = []
    collecting = False
    for page_number in (36, 37):  # zero-indexed PDF pages 37 and 38
        for block in document[page_number].get_text("dict")["blocks"]:
            for line in block.get("lines", []):
                text = "".join(span["text"] for span in line["spans"]).strip()
                x, y = line["bbox"][:2]
                if text.startswith("p = 0x"):
                    collecting = True
                    chunks.append(text.split("0x", 1)[1])
                elif collecting and text.startswith("M+"):
                    collecting = False
                elif collecting and text and x > 130 and 90 < y < 660:
                    chunks.append(text)
    hexadecimal = "".join(chunks)
    if len(hexadecimal) != 4098:
        raise AssertionError(f"NGCC-III p extraction length {len(hexadecimal)}")
    return int(hexadecimal, 16), hexadecimal


def main():
    print("environment")
    print("python", sys.version.split()[0])
    print("platform", platform.platform())
    import sympy
    print("sympy", sympy.__version__)
    input_path = Path("kex-08-spec.pdf")
    print("input_sha256", hashlib.sha256(input_path.read_bytes()).hexdigest())
    print()

    for name, p in PARAMETERS.items():
        plus = parse_expression(p["M_plus_expression"])
        minus = parse_expression(p["M_minus_expression"])
        plus_hex = int(p["M_plus_hex"], 16)
        minus_hex = int(p["M_minus_hex"], 16)
        plus_product = 1
        for prime, exponent in plus.items():
            plus_product *= prime**exponent
        minus_product = 1
        for prime, exponent in minus.items():
            minus_product *= prime**exponent

        assert plus_product == plus_hex, (name, "M+ mismatch")
        assert minus_product == minus_hex, (name, "M- mismatch")

        coordinates = sorted(
            [(prime, exponent) for prime, exponent in plus.items()]
            + [(prime, exponent) for prime, exponent in minus.items()]
        )
        N = 1
        for _, exponent in coordinates:
            N *= exponent + 1
        multiplicity_splits = {}
        for prime, _ in coordinates:
            multiplicity_splits[prime] = multiplicity_splits.get(prime, 0) + 1
        N_if_repeats_wrongly_split = 1
        for multiplicity in multiplicity_splits.values():
            N_if_repeats_wrongly_split *= multiplicity + 1
        M = plus_product * minus_product
        product_e_plus_1 = 1
        for _, exponent in coordinates:
            product_e_plus_1 *= exponent + 1
        assert product_e_plus_1 == N

        # If each coordinate were selected as 0..B*e_i, as in the ordinary
        # KeyGen style, B cancels from the key-space target equation.
        # Its product count is recorded here only as a comparison; this is
        # not the Algorithm 8 domain.
        target_bits = 2 * p["lambda"]
        target = 1 << target_bits
        floor_log2 = N.bit_length() - 1
        ceil_log2 = N.bit_length()
        headroom_floor = floor_log2 - target_bits
        headroom_ceil = ceil_log2 - target_bits
        p0 = Fraction(1, N)
        p_two = 1 - (1 - p0) ** 2

        exponent_multiset = {}
        for _, exponent in coordinates:
            exponent_multiset[exponent] = exponent_multiset.get(exponent, 0) + 1

        print(name)
        print("target_bits", target_bits)
        print("target", target)
        print("M_plus", plus_product)
        print("M_minus", minus_product)
        print("M", M)
        print("M_bit_length", M.bit_length())
        print("coordinate_count", len(coordinates))
        print("M_plus_distinct_count", len(plus))
        print("M_minus_distinct_count", len(minus))
        print("coordinate_exponents", coordinates)
        print("exponent_multiset", dict(sorted(exponent_multiset.items())))
        print("N=product(e_i+1)", N)
        print("N_bit_length", N.bit_length())
        print("floor_log2_N", floor_log2)
        print("ceil_log2_N_exact", ceil_log2)
        print("headroom_vs_target_using_floor", headroom_floor)
        print("headroom_vs_target_using_ceil", headroom_ceil)
        print("shortfall_vs_target_using_floor", -headroom_floor)
        print("shortfall_vs_target_using_ceil", -headroom_ceil)
        print("N_lt_target", N < target)
        print("target_over_N", target // N)
        print("all_zero_p0", f"{p0.numerator}/{p0.denominator}")
        print("all_zero_p0_floor_log2", -(N.bit_length()))
        print("all_zero_p0_ceil_log2", -floor_log2)
        print("two_party_at_least_one_zero", f"{p_two.numerator}/{p_two.denominator}")
        print("two_party_numerator", p_two.numerator)
        print("two_party_denominator", p_two.denominator)
        print("two_party_note", "=2/N-1/N^2")
        print()

    p3, hexadecimal = extract_ngcc3_p(input_path)
    factors3 = factorint(p3 + 1)
    rebuilt = 1
    for prime, exponent in factors3.items():
        rebuilt *= prime**exponent
    assert rebuilt == p3 + 1

    coordinates3 = sorted((int(prime), int(e)) for prime, e in factors3.items())
    N3 = 1
    for _, exponent in coordinates3:
        N3 *= exponent + 1
    exponent_multiset3 = {}
    for _, exponent in coordinates3:
        exponent_multiset3[exponent] = exponent_multiset3.get(exponent, 0) + 1
    target_bits = 1024
    target = 1 << target_bits
    floor_log2 = N3.bit_length() - 1
    ceil_log2 = N3.bit_length()
    p0 = Fraction(1, N3)
    p_two = 1 - (1 - p0) ** 2

    print("NGCC-III")
    print("p_hex_digits", len(hexadecimal))
    print("p_bit_length", p3.bit_length())
    print("factor_product_equals_p_plus_1", rebuilt == p3 + 1)
    print("factor_count", len(factors3))
    print("coordinate_count", len(coordinates3))
    print("exponent_multiset", dict(sorted(exponent_multiset3.items())))
    print("N=product(e_i+1)", N3)
    print("N_bit_length", N3.bit_length())
    print("floor_log2_N", floor_log2)
    print("ceil_log2_N_exact", ceil_log2)
    print("target_bits", target_bits)
    print("N_ge_target", N3 >= target)
    print("headroom_vs_target_using_floor", floor_log2 - target_bits)
    print("headroom_vs_target_using_ceil", ceil_log2 - target_bits)
    print("all_zero_p0", f"{p0.numerator}/{p0.denominator}")
    print("all_zero_p0_floor_log2", -(N3.bit_length()))
    print("all_zero_p0_ceil_log2", -floor_log2)
    print("two_party_at_least_one_zero", f"{p_two.numerator}/{p_two.denominator}")
    print("two_party_note", "=2/N-1/N^2")


if __name__ == "__main__":
    main()
