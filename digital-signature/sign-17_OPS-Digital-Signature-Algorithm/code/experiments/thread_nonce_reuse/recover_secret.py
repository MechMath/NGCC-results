#!/usr/bin/env python3
import pathlib
import struct
import sys

Q = 67104769
N = 512


def primitive_root(p):
    factors = (2, 3, 7, 27960319)
    for g in range(2, p):
        if all(pow(g, (p - 1) // f, p) != 1 for f in factors):
            return g
    raise RuntimeError("primitive root not found")


def eval_poly(coeffs, x):
    value = 0
    for c in reversed(coeffs):
        value = (value * x + c) % Q
    return value


def interpolate_from_evals(evals, omega):
    # For f(x)=sum a_i x^i and evals[j]=f(omega^(2j+1)),
    # the inverse relation is a_i = N^-1 omega^-i sum_j evals[j] omega^(-2ij).
    inv_n = pow(N, -1, Q)
    out = [0] * N
    for i in range(N):
        total = 0
        for j, y in enumerate(evals):
            total = (total + y * pow(omega, (-2 * i * j) % (2 * N), Q)) % Q
        out[i] = total * inv_n % Q * pow(omega, (-i) % (2 * N), Q) % Q
    return out


def read_i32(path):
    data = path.read_bytes()
    if len(data) != 4 * N:
        raise ValueError(f"{path}: expected {4*N} bytes, got {len(data)}")
    return list(struct.unpack(f"<{N}i", data))


def centered(a):
    a %= Q
    return a if a <= (Q - 1) // 2 else a - Q


def main():
    if len(sys.argv) != 2:
        raise SystemExit("usage: recover_secret.py ARTIFACT_DIR")
    root = pathlib.Path(sys.argv[1])
    c0 = read_i32(root / "c0.i32")
    c1 = read_i32(root / "c1.i32")
    challenge_difference = [(a - b) % Q for a, b in zip(c0, c1)]

    g = primitive_root(Q)
    omega = pow(g, (Q - 1) // (2 * N), Q)
    assert pow(omega, N, Q) == Q - 1
    assert pow(omega, 2 * N, Q) == 1

    inv_evals = []
    for j in range(N):
        x = pow(omega, 2 * j + 1, Q)
        value = eval_poly(challenge_difference, x)
        if value == 0:
            raise SystemExit(f"noninvertible challenge difference at point {j}")
        inv_evals.append(pow(value, -1, Q))
    inverse_challenge_difference = interpolate_from_evals(inv_evals, omega)

    all_match = True
    for poly_index in range(3):
        s1 = read_i32(root / f"s1_true_{poly_index}.i32")
        z0 = read_i32(root / f"z0_{poly_index}.i32")
        z1 = read_i32(root / f"z1_{poly_index}.i32")
        response_difference = [(a - b) % Q for a, b in zip(z0, z1)]

        inverse_evals = []
        for j in range(N):
            x = pow(omega, 2 * j + 1, Q)
            inverse_evals.append(
                eval_poly(response_difference, x)
                * pow(eval_poly(challenge_difference, x), -1, Q)
                % Q
            )
        recovered = [centered(v) for v in interpolate_from_evals(inverse_evals, omega)]
        mismatches = sum(a != b for a, b in zip(recovered, s1))
        all_match &= mismatches == 0
        (root / f"recovered_s1_{poly_index}.i32").write_bytes(
            struct.pack(f"<{N}i", *recovered)
        )
        print(
            f"poly={poly_index} coefficient_mismatches={mismatches} "
            f"recovered_sha_input={''.join(f'{centered(v):+d}' for v in recovered[:4])}"
        )

    print(f"all_three_s1_polynomials_recovered={int(all_match)}")
    return 0 if all_match else 1


if __name__ == "__main__":
    raise SystemExit(main())
