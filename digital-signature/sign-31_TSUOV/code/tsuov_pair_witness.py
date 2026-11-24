#!/usr/bin/env python3
"""Exact-arithmetic TSUOV-128 Eq. (37) / Algorithm 3 witness.

This script is intentionally self-contained and uses only the Python standard
library. It constructs the submitted q=31 degree-88 companion matrix, checks
the defining relation for g(z), builds every first-m1-columns matrix E_t, and
evaluates the pair and diagonal witnesses.
"""

from __future__ import annotations

import hashlib
import json
import platform
import sys
from pathlib import Path


Q = 31
ELL = 2
K = 11
M1 = 61
M2 = 88
N = 64
O = 4
V = N - O

SOURCE_URL = (
    "https://cdn.jsdelivr.net/gh/ngcc-dev/ngcc-harness@"
    "dc66c6cb3c06e75bdea0048e21fa4e13c63f00af/sign-31/sign-31-spec.pdf"
)
SOURCE_SHA256 = "17b2cb0d43a3f45c59fe79f2819bb6dcdc988fdc1a9776a40054d27761f5697a"


def mat_identity(size: int) -> list[list[int]]:
    return [[int(i == j) for j in range(size)] for i in range(size)]


def mat_mul(a: list[list[int]], b: list[list[int]]) -> list[list[int]]:
    rows = len(a)
    shared = len(b)
    cols = len(b[0])
    out = [[0] * cols for _ in range(rows)]
    for i in range(rows):
        out_i = out[i]
        for t in range(shared):
            ait = a[i][t]
            if ait == 0:
                continue
            bt = b[t]
            for j in range(cols):
                out_i[j] = (out_i[j] + ait * bt[j]) % Q
    return out


def mat_add_scaled(
    *terms: tuple[int, list[list[int]]]
) -> list[list[int]]:
    size = len(terms[0][1])
    out = [[0] * size for _ in range(size)]
    for scale, matrix in terms:
        for i in range(size):
            for j in range(size):
                out[i][j] = (out[i][j] + scale * matrix[i][j]) % Q
    return out


def companion_of_g() -> list[list[int]]:
    """Companion for z^88 = z^2 + 3z + 4, with last-column convention."""
    z = [[0] * M2 for _ in range(M2)]
    for i in range(M2 - 1):
        z[i + 1][i] = 1
    z[0][M2 - 1] = 4
    z[1][M2 - 1] = 3
    z[2][M2 - 1] = 1
    return z


def trim_poly(poly: list[int]) -> list[int]:
    while len(poly) > 1 and poly[-1] == 0:
        poly.pop()
    return poly


def poly_sub(a: list[int], b: list[int], p: int) -> list[int]:
    size = max(len(a), len(b))
    out = [0] * size
    for i in range(size):
        out[i] = (
            (a[i] if i < len(a) else 0) - (b[i] if i < len(b) else 0)
        ) % p
    return trim_poly(out)


def poly_divmod(
    a: list[int], b: list[int], p: int
) -> tuple[list[int], list[int]]:
    a = trim_poly(a[:])
    b = trim_poly(b[:])
    if b == [0]:
        raise ZeroDivisionError("polynomial division by zero")
    if len(a) < len(b):
        return [0], a
    quotient = [0] * (len(a) - len(b) + 1)
    inv_lead = pow(b[-1], -1, p)
    while len(a) >= len(b) and a != [0]:
        degree = len(a) - len(b)
        coefficient = a[-1] * inv_lead % p
        quotient[degree] = coefficient
        for i, value in enumerate(b):
            a[i + degree] = (a[i + degree] - coefficient * value) % p
        trim_poly(a)
    return trim_poly(quotient), a


def poly_gcd(a: list[int], b: list[int], p: int) -> list[int]:
    while b != [0]:
        _, remainder = poly_divmod(a, b, p)
        a, b = b, remainder
    inverse = pow(a[-1], -1, p)
    return [(value * inverse) % p for value in a]


def poly_mulmod(
    a: list[int], b: list[int], modulus: list[int], p: int
) -> list[int]:
    product = [0] * (len(a) + len(b) - 1)
    for i, ai in enumerate(a):
        for j, bj in enumerate(b):
            product[i + j] = (product[i + j] + ai * bj) % p
    _, remainder = poly_divmod(product, modulus, p)
    return remainder


def poly_powmod(
    base: list[int], exponent: int, modulus: list[int], p: int
) -> list[int]:
    result = [1]
    current = base
    while exponent:
        if exponent & 1:
            result = poly_mulmod(result, current, modulus, p)
        current = poly_mulmod(current, current, modulus, p)
        exponent >>= 1
    return result


def check_g_irreducible() -> dict[str, object]:
    # g(z) = z^88 - z^2 - 3z - 4.
    g = [0] * (M2 + 1)
    g[M2] = 1
    g[2] = -1 % Q
    g[1] = -3 % Q
    g[0] = -4 % Q
    x = [0, 1]
    h = x[:]
    checked = 0
    for degree in range(1, M2 // 2 + 1):
        h = poly_powmod(h, Q, g, Q)
        difference = poly_sub(h, x, Q)
        divisor = poly_gcd(g, difference, Q)
        if len(divisor) > 1:
            return {
                "irreducible": False,
                "degree_checked": degree,
                "nontrivial_factor": divisor,
            }
        checked += 1
    return {"irreducible": True, "degrees_checked": checked}


def eq40_exponent(i: int, j: int) -> int:
    """Zero-based form of Eq. (40) for 0 <= i <= j < k."""
    one_i = i + 1
    one_j = j + 1
    return (one_i - 1) * (2 * K - one_i + 2) // 2 + K - one_j


def sign_ctr(i: int, j: int) -> int:
    """Algorithm 2's descending-j counter for a pair."""
    row_offset = sum(K - t for t in range(i))
    return row_offset + (K - 1 - j)


def verify_ctr_displayed(i: int, j: int) -> int:
    """Algorithm 3 as displayed: ascending j after diagonal i."""
    row_offset = sum(K - t for t in range(i))
    return row_offset + (j - i)


def lin_field_element(a: int, b: int) -> tuple[int, int]:
    """pi_ell for Phi=[[1,8],[8,-1]]."""
    return ((a + 8 * b) % Q, (8 * a - b) % Q)


def dot_mod(a: list[int], b: list[int]) -> int:
    if len(a) != len(b):
        raise ValueError(f"dot-product dimension mismatch: {len(a)} vs {len(b)}")
    return sum(x * y for x, y in zip(a, b)) % Q


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def main() -> int:
    root = Path(__file__).resolve().parent
    pdf = root / "sign-31-spec.pdf"
    if not pdf.exists():
        raise FileNotFoundError(f"missing pinned source: {pdf}")
    actual_pdf_sha = sha256_file(pdf)
    if actual_pdf_sha != SOURCE_SHA256:
        raise RuntimeError(
            f"source hash mismatch: expected {SOURCE_SHA256}, got {actual_pdf_sha}"
        )

    z = companion_of_g()
    identity = mat_identity(M2)
    powers = [identity]
    for _ in range(M2):
        powers.append(mat_mul(powers[-1], z))
    relation = mat_add_scaled(
        (1, powers[2]), (3, powers[1]), (4, identity)
    )
    if powers[M2] != relation:
        raise AssertionError("companion matrix does not satisfy z^88=z^2+3z+4")

    e_matrices = [
        [[powers[exponent][row][column] for column in range(M1)]
         for row in range(M2)]
        for exponent in range(K * (K + 1) // 2)
    ]

    (z_path := root / "companion_Z.json").write_text(
        json.dumps(z, separators=(",", ":")), encoding="utf-8"
    )
    (e_path := root / "E_matrices.json").write_text(
        json.dumps(e_matrices, separators=(",", ":")), encoding="utf-8"
    )

    # Primary off-diagonal pair: zero-based (0,10), one-based (1,11). Equation
    # (40) assigns E_0. The displayed Verify loop reaches this pair at ctr=10,
    # so its actual generated matrix select is audited separately below.
    pair_i = 0
    pair_j = 10
    pair_exponent = eq40_exponent(pair_i, pair_j)
    if pair_exponent != 0:
        raise AssertionError("unexpected Eq. (40) exponent")
    coord_s = 0
    coord_a = 0
    e_pair = e_matrices[pair_exponent][coord_s][coord_a]
    if e_pair != 1:
        raise AssertionError("selected generated E coordinate is not one")

    # Actual sparse public block. S'=0 and P_1,2=0 imply P_1,3=0 by Eq. (34).
    # The only entry of P_1,1 is (0,0)=1, represented in F_31[lambda].
    public_block = {
        "index_a_zero_based": coord_a,
        "S_prime": 0,
        "P_a_1_nonzero_entries": [[0, 0, 1]],
        "P_a_2_nonzero_entries": [],
        "P_a_3_nonzero_entries": [],
        "symmetric": True,
    }
    x = [1, 0]  # x_i=x_j=(1,0) in F_31^2.
    bilinear_B = 1  # x^T P_a x with the sole P_a,1[0,0]=1.
    polar_Pp = 2 * bilinear_B % Q  # P'(x,x)=P(2x)-2P(x)=2P(x).
    sign_U_diagonal = 1  # Algorithm 2's pi_1(x^T P_a,1 x).

    eq37_cross_token = polar_Pp * e_pair % Q
    alg3_semantic_cross_token = bilinear_B * e_pair % Q
    if 2 * e_pair % Q == e_pair:
        raise AssertionError("the field coordinate must distinguish 2E from E")

    # Auxiliary non-identity coordinate from the same g-generated family:
    # pair (0,9) maps to E_1, whose coordinate (1,0) is one.
    auxiliary_i = 0
    auxiliary_j = 9
    auxiliary_exponent = eq40_exponent(auxiliary_i, auxiliary_j)
    auxiliary_s = 1
    auxiliary_a = 0
    auxiliary_e = e_matrices[auxiliary_exponent][auxiliary_s][auxiliary_a]
    if auxiliary_exponent != 1 or auxiliary_e != 1:
        raise AssertionError("unexpected non-identity E_1 witness")

    # Full output vectors under the intended verifier semantics, where U_ij is
    # the same bilinear value computed by Algorithm 2. Only pairs (0,0),
    # (10,10), and (0,10) are nonzero. The diagonal pair (0,0) uses Eq. (40)
    # exponent 10, not 0.
    diagonal_0_exponent = eq40_exponent(0, 0)
    diagonal_10_exponent = eq40_exponent(10, 10)
    eq37_full = [0] * M2
    alg3_displayed_full = [0] * M2
    displayed_pair_ctr = verify_ctr_displayed(pair_i, pair_j)
    displayed_pair_exponent = displayed_pair_ctr
    displayed_pair_e = e_matrices[displayed_pair_exponent][coord_s][coord_a]
    displayed_diagonal_0_exponent = verify_ctr_displayed(0, 0)
    displayed_diagonal_10_exponent = verify_ctr_displayed(10, 10)
    for row in range(M2):
        eq37_diagonal_value = (
            bilinear_B * e_matrices[diagonal_0_exponent][row][coord_a]
            + bilinear_B * e_matrices[diagonal_10_exponent][row][coord_a]
        ) % Q
        alg3_displayed_diagonal_value = (
            bilinear_B
            * e_matrices[displayed_diagonal_0_exponent][row][coord_a]
            + bilinear_B
            * e_matrices[displayed_diagonal_10_exponent][row][coord_a]
        ) % Q
        eq37_full[row] = (
            eq37_diagonal_value
            + polar_Pp * e_matrices[pair_exponent][row][coord_a]
        ) % Q
        alg3_displayed_full[row] = (
            alg3_displayed_diagonal_value
            + bilinear_B
            * e_matrices[displayed_pair_exponent][row][coord_a]
        ) % Q
    if eq37_full[coord_s] != 2 or alg3_displayed_full[coord_s] != 1:
        raise AssertionError("unexpected full output at selected coordinate")

    # Diagonal control (1,1), coordinate (10,0), using E_10.
    diagonal_exponent = diagonal_0_exponent
    diagonal_coord_s = 10
    diagonal_coord_a = 0
    diagonal_e = e_matrices[diagonal_exponent][diagonal_coord_s][diagonal_coord_a]
    eq37_diagonal = bilinear_B * diagonal_e % Q
    sign_diagonal = sign_U_diagonal * diagonal_e % Q
    if diagonal_exponent != 10 or diagonal_e != 1:
        raise AssertionError("unexpected diagonal E coordinate")

    # Audit the literal displayed projection in Algorithm 3. For s=e_0,
    # pi_ell(s)=(1,8) in each active block. The displayed c=pi_ell(s_i^T P)
    # has 2*n=128 entries, while the PDF annotation says c in F_q^n (64).
    pi_e0 = list(lin_field_element(1, 0))
    projection_dot = dot_mod(pi_e0, pi_e0)
    displayed_c_length = N * ELL
    displayed_c_annotation_length = N
    phi_gram_scalar = projection_dot  # Phi^T Phi = 3 I_2.

    irreducibility = check_g_irreducible()
    witness = {
        "classification": "proof-producing computation; not crypto_run evidence",
        "source": {
            "url": SOURCE_URL,
            "sha256": actual_pdf_sha,
            "version_read": "TSUOV v1.0, 29 June 2026",
        },
        "environment": {
            "python": sys.version,
            "platform": platform.platform(),
            "arithmetic": "standard-library exact integers reduced modulo 31",
            "checkpoint": "2026-11-20 research session",
        },
        "parameters": {
            "q": Q, "ell": ELL, "n": N, "o": O, "v": V,
            "m1": M1, "m2": M2, "k": K,
            "g": "z^88 - z^2 - 3z - 4",
            "Phi": [[1, 8], [8, -1]],
        },
        "companion": {
            "convention": "last-column companion; column a is Z e_a",
            "relation_checked": "Z^88 = Z^2 + 3Z + 4I",
            "relation_holds": powers[M2] == relation,
            "g_irreducibility_check": irreducibility,
            "sha256": sha256_file(z_path),
        },
        "E_construction": {
            "definition": "E_t is the first m1 columns of Z^t",
            "count": len(e_matrices),
            "sha256": sha256_file(e_path),
        },
        "off_diagonal": {
            "pair_zero_based": [pair_i, pair_j],
            "pair_one_based": [pair_i + 1, pair_j + 1],
            "eq40_exponent": pair_exponent,
            "sign_descending_ctr": sign_ctr(pair_i, pair_j),
            "verify_ascending_ctr_if_taken_literally": verify_ctr_displayed(
                pair_i, pair_j
            ),
            "coordinate_zero_based_s_a": [coord_s, coord_a],
            "E_coordinate": e_pair,
            "public_block": public_block,
            "x_i": x,
            "x_j": x,
            "bilinear_B_x_i_x_j": bilinear_B,
            "eq37_polar_Pprime": polar_Pp,
            "eq37_cross_output": eq37_cross_token,
            "alg3_unordered_pair_output_intended_semantics":
                alg3_semantic_cross_token,
            "alg3_displayed_pair_matrix": {
                "ctr": displayed_pair_ctr,
                "E_exponent": displayed_pair_exponent,
                "E_coordinate_at_selected_s_a": displayed_pair_e,
                "contribution_at_selected_coordinate":
                    bilinear_B * displayed_pair_e % Q,
            },
            "multiplier_check": {
                "E": e_pair,
                "2E mod 31": 2 * e_pair % Q,
                "2E_equals_E": 2 * e_pair % Q == e_pair,
            },
            "full_output_prefix_eq37": eq37_full[0:2],
            "full_output_prefix_alg3_displayed":
                alg3_displayed_full[0:1],
            "auxiliary_nonidentity_generated_coordinate": {
                "pair_zero_based": [auxiliary_i, auxiliary_j],
                "pair_one_based": [auxiliary_i + 1, auxiliary_j + 1],
                "eq40_exponent": auxiliary_exponent,
                "sign_descending_ctr": sign_ctr(auxiliary_i, auxiliary_j),
                "verify_ascending_ctr_if_taken_literally":
                    verify_ctr_displayed(auxiliary_i, auxiliary_j),
                "coordinate_zero_based_s_a": [auxiliary_s, auxiliary_a],
                "E_coordinate": auxiliary_e,
                "eq37_cross_output": polar_Pp * auxiliary_e % Q,
                "alg3_unordered_pair_output_intended_semantics":
                    bilinear_B * auxiliary_e % Q,
            },
        },
        "diagonal_control": {
            "pair_zero_based": [0, 0],
            "pair_one_based": [1, 1],
            "eq40_exponent": diagonal_exponent,
            "coordinate_zero_based_s_a": [diagonal_coord_s, diagonal_coord_a],
            "E_coordinate": diagonal_e,
            "public_x": x,
            "P_x": bilinear_B,
            "polar_Pprime_x_x": polar_Pp,
            "eq37_diagonal_term": eq37_diagonal,
            "sign_derivative_U_diagonal": sign_diagonal,
            "interpretation": (
                "diagonal uses P(x), while the i<j polar term uses 2P(x)"
            ),
        },
        "displayed_projection_audit": {
            "status": "independent pseudocode/type inconsistency",
            "pi_ell_e0": pi_e0,
            "PhiT_Phi_over_F31": [[3, 0], [0, 3]],
            "projection_dot_for_unit_field_element": projection_dot,
            "literals_dot_equals_three_times_sign_bilinear": True,
            "literal_dot_equals_PhiT_Phi_scalar_factor": phi_gram_scalar,
            "printed_c_length_if_c_equals_pi_ell_of_n_vector":
                displayed_c_length,
            "pdf_annotation_c_length": displayed_c_annotation_length,
            "dimension_mismatch": True,
            "note": (
                "The factor-two map witness is evaluated under the intended "
                "U_ij=s_i^T P s_j semantics used by Sign. The displayed c/dot "
                "line is not silently treated as a well-typed implementation."
            ),
        },
        "scope": {
            "proved": (
                "One deterministic TSUOV-128 public-map witness distinguishes "
                "Eq. (37)'s cross-polar term from both the intended unordered-"
                "pair value and the generated matrix selected by the displayed "
                "Algorithm 3 loop at actual E-matrix coordinates."
            ),
            "not_proved": (
                "No signature forgery, hash preimage, key recovery, full "
                "implementation equivalence, or general security-level claim."
            ),
        },
    }
    output_path = root / "witness-output.json"
    output_path.write_text(
        json.dumps(witness, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    summary = {
        "witness_output_sha256": sha256_file(output_path),
        "primary_E_coordinate": e_pair,
        "eq37_cross": eq37_cross_token,
        "alg3_cross_intended": alg3_semantic_cross_token,
        "2E": 2 * e_pair % Q,
        "diagonal_eq37": eq37_diagonal,
        "diagonal_sign": sign_diagonal,
        "literal_projection_dot": projection_dot,
        "literal_c_length": displayed_c_length,
        "annotated_c_length": displayed_c_annotation_length,
    }
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
