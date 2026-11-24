#!/usr/bin/env python3
"""Structural witness for the displayed TSUOV Algorithms 2/3 mismatch.

Only the q=31, ell=2, odd-characteristic Table 1 profiles from the pinned
specification are used.  This checks the exact index sets and block shapes in
the displayed pseudocode; it does not implement an unavailable PRG/XOF.
"""

PROFILES = [
    ("TSUOV-128", 64, 4, 61, 88, 11),
    ("TSUOV-256", 119, 5, 114, 160, 16),
    ("TSUOV-512", 230, 12, 218, 240, 10),
]


def pair_order(k):
    """Sign and Verify both enumerate (i,j) in this order."""
    return [(i, j) for i in range(k) for j in range(k - 1, i - 1, -1)]


def check_profile(name, n, o, m1, m2, k):
    v = n - o

    # Algorithm 3 line 9 places P_{r,2} in its upper-left v-by-v block,
    # although the immediately preceding annotation declares P_{r,2} is
    # v-by-o.  The correct public block P_{r,1} is v-by-v.
    displayed_shape = (v, o, v)
    required_shape = (v, v)
    assert displayed_shape[0:2] == (v, o)
    assert v > o

    # Signing uses PRG indices 0,...,2m1-1.  Verify uses
    # 2,...,2m1+1 and therefore omits both signer indices 0,1.
    sign_indices = set(range(2 * m1))
    verify_indices = {2 * r + b for r in range(1, m1 + 1) for b in range(2)}
    omitted = sign_indices - verify_indices
    assert omitted == {0, 1}

    pairs = pair_order(k)
    assert len(pairs) == k * (k + 1) // 2
    assert pairs[0] == (0, k - 1)
    assert pairs[-1] == (k - 1, k - 1)

    # With no aliasing, each cross pair adds E*M_j to A_i and E*M_i to A_j.
    # At i=j the same A_i object receives both updates, exactly 2E*M_i.
    diagonal_updates = [len([1 for (a, b) in pairs if a == i and b == i]) * 2
                        for i in range(k)]
    assert diagonal_updates == [2] * k
    off_diagonal = [(i, j) for (i, j) in pairs if i < j]
    assert len(off_diagonal) == k * (k - 1) // 2

    return {
        "profile": name,
        "v,o": (v, o),
        "displayed_upper_left_shape": displayed_shape,
        "required_upper_left_shape": required_shape,
        "sign_prg_indices_omitted_by_verify": sorted(omitted),
        "pair_count": len(pairs),
        "first_ctr_pair": pairs[0],
        "diagonal_E_contribution": 2,
        "cross_updates": "A_i+=E_ij*M_j, A_j+=E_ij*M_i",
    }


def main():
    for profile in PROFILES:
        print(check_profile(*profile))


if __name__ == "__main__":
    main()
