#!/usr/bin/env python3
"""Reproduce the OPS-SIG MLWE primal-uSVP core-SVP margin calculation.

This is an estimator calculation, not a proof of security or an attack.
It implements the standard GSA/ADPS16 threshold used by the lattice-estimator
primal-uSVP routine (release observed 2026-11-14), with uniform bounded
coefficients approximated by a discrete Gaussian of the same variance.
"""

import json
import math


Q = 67_104_769
PROFILES = [
    {"name": "OPSsig-128", "n": 512, "k": 3, "l": 3, "eta": 2,
     "classical_target": 128, "quantum_target": 80},
    {"name": "OPSsig-256", "n": 512, "k": 4, "l": 4, "eta": 3,
     "classical_target": 256, "quantum_target": 128},
    {"name": "OPSsig-512", "n": 1024, "k": 4, "l": 4, "eta": 2,
     "classical_target": 512, "quantum_target": 256},
]


def delta(beta):
    """GSA root-Hermite factor for a block size beta >= 40."""
    return (beta / (2 * math.pi * math.e)
            * (math.pi * beta) ** (1 / beta)) ** (1 / (2 * (beta - 1)))


def solve_embedding_dimension(n, m, beta, tau, sigma):
    """Port of PrimalUSVP._solve_for_d for equal secret/error scales."""
    log_delta = math.log(delta(beta))
    a = -log_delta
    c = math.log(tau) - (n + 1) * math.log(Q)
    constant = 0.5 * math.log(sigma * sigma * (beta - 1) + tau * tau)
    b = log_delta * (2 * beta - 1) + math.log(Q) - constant

    if a * n * n + b * n + c >= 0:
        return n
    discriminant = b * b - 4 * a * c
    if discriminant < 0:
        return None
    d1 = (-b + math.sqrt(discriminant)) / (2 * a)
    d2 = (-b - math.sqrt(discriminant)) / (2 * a)
    if a > 0:
        return min(m, math.ceil(d2))
    if n <= d1:
        return min(m, math.ceil(d1))
    return None


def primal_usvp(profile):
    n_degree = profile["n"]
    secret_dim = profile["l"] * n_degree
    sample_count = profile["k"] * n_degree
    # Bai-Galbraith dimension increase for equal-size small secret and error.
    available_dim = sample_count + secret_dim
    variance = profile["eta"] * (profile["eta"] + 1) / 3
    sigma = math.sqrt(variance)

    row = None
    for beta in range(40, available_dim + 1):
        d = solve_embedding_dimension(
            secret_dim, available_dim, beta, sigma, sigma
        )
        if d is None:
            continue
        if d < beta:
            d = beta
        if d == beta and d < available_dim:
            d += 1
        if d > available_dim + 1:
            continue

        lhs = math.log(math.sqrt(sigma * sigma * (beta - 1) + sigma * sigma))
        rhs = (math.log(delta(beta)) * (2 * beta - d - 1)
               + (math.log(sigma) + math.log(Q) * (d - secret_dim - 1)) / d)
        if lhs <= rhs:
            row = {
                "block_size": beta,
                "embedding_dimension": d,
                "root_hermite_delta": delta(beta),
                "classical_core_svp_log2": 0.292 * beta,
                "quantum_core_svp_log2": 0.265 * beta,
                "classical_sieve_memory_log2": 0.2075 * beta,
                "classical_margin_bits": 0.292 * beta - profile["classical_target"],
                "quantum_margin_bits": 0.265 * beta - profile["quantum_target"],
            }
            break

    return {
        **profile,
        "q_log2": math.log2(Q),
        "secret_dimension": secret_dim,
        "sample_count": sample_count,
        "coefficient_variance": variance,
        "primal_usvp": row,
    }


def main():
    results = {
        "status": "conditional_estimator_result",
        "model": {
            "attack": "MLWE primal uSVP with Bai-Galbraith embedding",
            "basis_shape": "GSA",
            "reduction_cost": "ADPS16 core-SVP with classical 2^(0.292 beta) and quantum 2^(0.265 beta)",
            "memory": "classical sieve list 2^(0.2075 beta) vectors",
            "success_probability": "standard heuristic success criterion; not a rigorous probability certificate",
            "queries": "zero signing-oracle queries; public key alone",
        },
        "profiles": [primal_usvp(profile) for profile in PROFILES],
        "limitations": [
            "The bounded uniform coefficient laws are approximated by matching-variance discrete Gaussians.",
            "The result is an estimator result, not an upper bound on all MLWE algorithms.",
            "A short MSIS vector does not by itself yield a verifier-accepted signature.",
            "The exact operational NGCC Low threshold is absent from the contract.",
        ],
    }
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
