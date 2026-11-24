"""Independent GF(2) consistency check for uBlock-1024 schedule prefixes."""

from analyze_keyschedule import F, G, rcs


def key_word_perm():
    # p[destination nibble] = source nibble. Each listed f[j] or g[j] is the
    # source position within the corresponding destination word.
    sources = [2, 5, 1, 0, 3, 6, 7, 4]
    perms = [F, G, F, G, F, G, F, G]
    p = [0] * 256
    for dst_word, (src_word, q) in enumerate(zip(sources, perms)):
        for dst_nibble in range(32):
            p[32 * dst_word + dst_nibble] = 32 * src_word + q[dst_nibble]
    return p


def apply_prefix_to_zero(prefix):
    out = [0] * 256
    p = key_word_perm()
    for rc in rcs[:prefix]:
        out = [out[p[i]] for i in range(256)]
        for j in range(8):
            out[64 + F[j]] ^= (rc >> (4 * j)) & 15
    return out


def compose_linear(p, prefix):
    q = list(range(256))
    for _ in range(prefix):
        q = [p[q[i]] for i in range(256)]
    return q


def consistent_affine_system(p, c):
    """Decide whether x[p[i]] xor x[i] = c[i] has a byte-vector solution."""
    basis = {}
    for dst in range(256):
        src = p[dst]
        for bit in range(4):
            row = (1 << (4 * src + bit)) ^ (1 << (4 * dst + bit))
            rhs = (c[dst] >> bit) & 1
            while row:
                pivot = row.bit_length() - 1
                if pivot in basis:
                    row ^= basis[pivot][0]
                    rhs ^= basis[pivot][1]
                else:
                    basis[pivot] = (row, rhs)
                    break
            if not row and rhs:
                return False
    return True


def main():
    p = key_word_perm()
    for prefix in range(1, 13):
        q = compose_linear(p, prefix)
        c = apply_prefix_to_zero(prefix)
        print(prefix, consistent_affine_system(q, c))


if __name__ == "__main__":
    main()
