#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "drng.h"

/*
 * Include the exact submitted Facto-DSA-128 Reference translation unit.
 * No submitted source is modified.
 */
#include "SIG_AlgorithmInstance.c"

DRNG_ctx drng_algorithm;

#define SLICE_DIM 11
#define CUBIC_TERMS_I FACTO_CUBIC_TERMS
#define SLICE_TERMS (((SLICE_DIM + 2) * (SLICE_DIM + 1) * SLICE_DIM) / 6)

static uint64_t splitmix64(uint64_t *state)
{
    uint64_t z = (*state += UINT64_C(0x9e3779b97f4a7c15));
    z = (z ^ (z >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
    z = (z ^ (z >> 27)) * UINT64_C(0x94d049bb133111eb);
    return z ^ (z >> 31);
}

static int matrix_rank(fe_t *a, int rows, int cols)
{
    int rank = 0;
    for (int col = 0; col < cols && rank < rows; ++col) {
        int pivot = -1;
        for (int r = rank; r < rows; ++r) {
            if (a[r * cols + col] != 0) {
                pivot = r;
                break;
            }
        }
        if (pivot < 0) {
            continue;
        }
        if (pivot != rank) {
            for (int c = 0; c < cols; ++c) {
                fe_t tmp = a[rank * cols + c];
                a[rank * cols + c] = a[pivot * cols + c];
                a[pivot * cols + c] = tmp;
            }
        }
        fe_t inv = f_inv(a[rank * cols + col]);
        for (int c = 0; c < cols; ++c) {
            a[rank * cols + c] = f_mul(a[rank * cols + c], inv);
        }
        for (int r = 0; r < rows; ++r) {
            if (r == rank || a[r * cols + col] == 0) {
                continue;
            }
            fe_t factor = a[r * cols + col];
            for (int c = 0; c < cols; ++c) {
                a[r * cols + c] = f_sub(
                    a[r * cols + c],
                    f_mul(factor, a[rank * cols + c]));
            }
        }
        ++rank;
    }
    return rank;
}

static int monomial_index(int a, int b, int c)
{
    int idx = 0;
    for (int i = 0; i < SLICE_DIM; ++i) {
        for (int j = i; j < SLICE_DIM; ++j) {
            for (int k = j; k < SLICE_DIM; ++k, ++idx) {
                if (i == a && j == b && k == c) {
                    return idx;
                }
            }
        }
    }
    return -1;
}

static int cubic_public_index(int i, int j, int k)
{
    int idx = 0;
    for (int a = 0; a < FACTO_V; ++a) {
        for (int b = a; b < FACTO_V; ++b) {
            for (int c = b; c < FACTO_V; ++c, ++idx) {
                if (a == i && b == j && c == k) {
                    return idx;
                }
            }
        }
    }
    return -1;
}

static int make_slice(fe_t *slice, uint64_t seed)
{
    for (int attempt = 0; attempt < 1024; ++attempt) {
        uint64_t state = seed ^ (UINT64_C(0xd1b54a32d192ed03) * (uint64_t)(attempt + 1));
        for (int i = 0; i < FACTO_V; ++i) {
            for (int j = 0; j < SLICE_DIM; ++j) {
                slice[i * SLICE_DIM + j] =
                    (fe_t)(splitmix64(&state) % (uint64_t)P);
            }
        }
        fe_t copy[FACTO_V * SLICE_DIM];
        memcpy(copy, slice, sizeof copy);
        if (matrix_rank(copy, FACTO_V, SLICE_DIM) == SLICE_DIM) {
            return attempt;
        }
    }
    return -1;
}

static int restricted_cubics(const unsigned char *pk,
                             const fe_t *slice,
                             fe_t *out)
{
    memset(out, 0, (size_t)FACTO_M * SLICE_TERMS * sizeof(fe_t));

    for (int i = 0; i < FACTO_V; ++i) {
        for (int j = i; j < FACTO_V; ++j) {
            for (int k = j; k < FACTO_V; ++k) {
                int src = cubic_public_index(i, j, k);
                if (src < 0) {
                    return -1;
                }
                for (int r = 0; r < FACTO_M; ++r) {
                    fe_t c = load_fe(
                        pk + ((size_t)r * CUBIC_TERMS_I + (size_t)src) * FE_BYTES);
                    if (!c) {
                        continue;
                    }
                    for (int a0 = 0; a0 < SLICE_DIM; ++a0) {
                        fe_t x0 = slice[i * SLICE_DIM + a0];
                        if (!x0) {
                            continue;
                        }
                        for (int a1 = 0; a1 < SLICE_DIM; ++a1) {
                            fe_t x1 = slice[j * SLICE_DIM + a1];
                            if (!x1) {
                                continue;
                            }
                            fe_t cx01 = f_mul(f_mul(c, x0), x1);
                            for (int a2 = 0; a2 < SLICE_DIM; ++a2) {
                                fe_t x2 = slice[k * SLICE_DIM + a2];
                                if (!x2) {
                                    continue;
                                }
                                int x = a0, y = a1, z = a2;
                                if (x > y) {
                                    int t = x;
                                    x = y;
                                    y = t;
                                }
                                if (y > z) {
                                    int t = y;
                                    y = z;
                                    z = t;
                                }
                                if (x > y) {
                                    int t = x;
                                    x = y;
                                    y = t;
                                }
                                int dst = monomial_index(x, y, z);
                                if (dst < 0) {
                                    return -2;
                                }
                                out[(size_t)r * SLICE_TERMS + (size_t)dst] =
                                    f_add(out[(size_t)r * SLICE_TERMS + (size_t)dst],
                                          f_mul(cx01, x2));
                            }
                        }
                    }
                }
            }
        }
    }
    return 0;
}

static int public_jacobian(const unsigned char *pk, const fe_t *z, fe_t *jac)
{
    fe_t plus[FACTO_V];
    fe_t minus[FACTO_V];
    fe_t pp[FACTO_M];
    fe_t pm[FACTO_M];
    fe_t pw[FACTO_M];
    fe_t inv2 = f_inv(2);

    for (int a = 0; a < FACTO_V; ++a) {
        memcpy(plus, z, sizeof plus);
        memcpy(minus, z, sizeof minus);
        plus[a] = f_add(plus[a], 1);
        minus[a] = f_sub(minus[a], 1);
        fe_t w[FACTO_V] = {0};
        w[a] = 1;
        if (eval_public_key(pk, plus, pp) != 0 ||
            eval_public_key(pk, minus, pm) != 0 ||
            eval_public_key(pk, w, pw) != 0) {
            return -1;
        }
        for (int r = 0; r < FACTO_M; ++r) {
            fe_t polar = f_sub(pp[r], pm[r]);
            polar = f_sub(polar, f_mul(2, pw[r]));
            jac[r * FACTO_V + a] = f_mul(polar, inv2);
        }
    }
    return 0;
}

static int nullspace_basis(const fe_t *a_in, int rows, int cols, fe_t *basis)
{
    fe_t *a = calloc((size_t)rows * cols, sizeof(fe_t));
    int pivot_cols[FACTO_V];
    int rank = 0;
    if (!a) {
        return -1;
    }
    memcpy(a, a_in, (size_t)rows * cols * sizeof(fe_t));

    for (int col = 0; col < cols && rank < rows; ++col) {
        int pivot = -1;
        for (int r = rank; r < rows; ++r) {
            if (a[r * cols + col]) {
                pivot = r;
                break;
            }
        }
        if (pivot < 0) {
            continue;
        }
        if (pivot != rank) {
            for (int c = 0; c < cols; ++c) {
                fe_t tmp = a[rank * cols + c];
                a[rank * cols + c] = a[pivot * cols + c];
                a[pivot * cols + c] = tmp;
            }
        }
        fe_t inv = f_inv(a[rank * cols + col]);
        for (int c = 0; c < cols; ++c) {
            a[rank * cols + c] = f_mul(a[rank * cols + c], inv);
        }
        for (int r = 0; r < rows; ++r) {
            if (r == rank || !a[r * cols + col]) {
                continue;
            }
            fe_t factor = a[r * cols + col];
            for (int c = 0; c < cols; ++c) {
                a[r * cols + c] =
                    f_sub(a[r * cols + c], f_mul(factor, a[rank * cols + c]));
            }
        }
        pivot_cols[rank++] = col;
    }

    int out_col = 0;
    for (int col = 0; col < cols; ++col) {
        int is_pivot = 0;
        for (int i = 0; i < rank; ++i) {
            is_pivot |= pivot_cols[i] == col;
        }
        if (is_pivot) {
            continue;
        }
        memset(basis + (size_t)out_col * cols, 0, (size_t)cols * sizeof(fe_t));
        basis[(size_t)out_col * cols + col] = 1;
        for (int i = 0; i < rank; ++i) {
            basis[(size_t)out_col * cols + pivot_cols[i]] =
                f_neg(a[i * cols + col]);
        }
        ++out_col;
    }
    free(a);
    return out_col;
}

static int generate_key(unsigned char **pk_out, unsigned char **sk_out)
{
    unsigned char seed[64];
    for (size_t i = 0; i < sizeof seed; ++i) {
        seed[i] = (unsigned char)(0x5Au + 17u * i);
    }
    if (init_random_number(&drng_algorithm, seed, sizeof seed) != 0) {
        return -1;
    }
    unsigned long long pk_len = sig_get_pk_len_bytes();
    unsigned long long sk_len = sig_get_sk_len_bytes();
    unsigned char *pk = calloc((size_t)pk_len, 1);
    unsigned char *sk = calloc((size_t)sk_len, 1);
    if (!pk || !sk) {
        free(pk);
        free(sk);
        return -2;
    }
    int rc = sig_keygen(pk, &pk_len, sk, &sk_len);
    if (rc != 0) {
        free(pk);
        free(sk);
        return -3;
    }
    *pk_out = pk;
    *sk_out = sk;
    return 0;
}

static int dump_slice(const unsigned char *pk, const unsigned char *sk,
                      const fe_t *slice, int attempt)
{
    fe_t *restricted = calloc((size_t)FACTO_M * SLICE_TERMS,
                              sizeof(fe_t));
    if (!restricted) {
        return -1;
    }
    if (restricted_cubics(pk, slice, restricted) != 0) {
        free(restricted);
        return -2;
    }

    fe_t sinv[SK_SINV_ELEMS];
    fe_t s[SK_SINV_ELEMS];
    if (sk_load_fe_array(sk, SK_SINV_OFFSET, sinv, SK_SINV_ELEMS) != 0 ||
        matrix_inverse(sinv, s, FACTO_V) != 0) {
        free(restricted);
        return -3;
    }
    fe_t l2u[FACTO_N * SLICE_DIM];
    for (int r = 0; r < FACTO_N; ++r) {
        for (int c = 0; c < SLICE_DIM; ++c) {
            fe_t acc = 0;
            for (int i = 0; i < FACTO_V; ++i) {
                acc = f_add(acc,
                            f_mul(s[(FACTO_N + r) * FACTO_V + i],
                                  slice[i * SLICE_DIM + c]));
            }
            l2u[r * SLICE_DIM + c] = acc;
        }
    }
    fe_t l2u_copy[FACTO_N * SLICE_DIM];
    memcpy(l2u_copy, l2u, sizeof l2u_copy);
    int rank = matrix_rank(l2u_copy, FACTO_N, SLICE_DIM);

    fe_t hidden_line_basis[SLICE_DIM];
    int nullity = nullspace_basis(l2u, FACTO_N, SLICE_DIM, hidden_line_basis);

    fe_t slice_rank_copy[FACTO_V * SLICE_DIM];
    memcpy(slice_rank_copy, slice, sizeof slice_rank_copy);
    int slice_rank = matrix_rank(slice_rank_copy, FACTO_V, SLICE_DIM);

    printf("{\n");
    printf("  \"schema\": \"facto-dsa-128-k2-slice/v1\",\n");
    printf("  \"source_sha256\": \"b76d3aa728cbc3d8e247129d326872a857143aa2e2ed4c8c7daca607f415a698\",\n");
    printf("  \"q\": %d,\n", P);
    printf("  \"slice_dim\": %d,\n", SLICE_DIM);
    printf("  \"slice_attempt\": %d,\n", attempt);
    printf("  \"slice_rank\": %d,\n", slice_rank);
    printf("  \"l2_slice_rank\": %d,\n", rank);
    printf("  \"hidden_intersection_dim\": %d,\n", nullity);
    printf("  \"slice\": [");
    for (int i = 0; i < FACTO_V * SLICE_DIM; ++i) {
        printf("%s%d", i ? "," : "", slice[i]);
    }
    printf("],\n");
    printf("  \"hidden_intersection_basis\": [");
    for (int i = 0; i < SLICE_DIM; ++i) {
        printf("%s%d", i ? "," : "", hidden_line_basis[i]);
    }
    printf("],\n");
    printf("  \"equations\": [\n");
    for (int r = 0; r < FACTO_M; ++r) {
        printf("    [");
        for (int i = 0; i < SLICE_TERMS; ++i) {
            printf("%s%d", i ? "," : "",
                   restricted[(size_t)r * SLICE_TERMS + (size_t)i]);
        }
        printf("]%s\n", r + 1 == FACTO_M ? "" : ",");
    }
    printf("  ]\n");
    printf("}\n");
    free(restricted);
    return 0;
}

static int check_candidate(const unsigned char *pk,
                           const unsigned char *sk,
                           const fe_t *slice,
                           const fe_t *candidate)
{
    fe_t z[FACTO_V];
    for (int i = 0; i < FACTO_V; ++i) {
        fe_t acc = 0;
        for (int j = 0; j < SLICE_DIM; ++j) {
            acc = f_add(acc, f_mul(slice[i * SLICE_DIM + j], candidate[j]));
        }
        z[i] = acc;
    }
    fe_t p[FACTO_M];
    if (eval_public_key(pk, z, p) != 0) {
        return -1;
    }
    int all_zero = 1;
    for (int i = 0; i < FACTO_M; ++i) {
        all_zero &= p[i] == 0;
    }

    fe_t jac[FACTO_M * FACTO_V];
    if (public_jacobian(pk, z, jac) != 0) {
        return -2;
    }
    fe_t jac_rank_input[FACTO_M * FACTO_V];
    memcpy(jac_rank_input, jac, sizeof jac_rank_input);
    int rank = matrix_rank(jac_rank_input, FACTO_M, FACTO_V);

    fe_t kernel_basis[FACTO_V * FACTO_V];
    memset(kernel_basis, 0, sizeof kernel_basis);
    int kernel_dim = nullspace_basis(jac, FACTO_M, FACTO_V, kernel_basis);

    fe_t sinv[SK_SINV_ELEMS];
    fe_t s[SK_SINV_ELEMS];
    int truth_ok =
        sk_load_fe_array(sk, SK_SINV_OFFSET, sinv, SK_SINV_ELEMS) == 0 &&
        matrix_inverse(sinv, s, FACTO_V) == 0;
    int truth_contained = 1;
    if (truth_ok && kernel_dim == FACTO_N) {
        for (int b = 0; b < FACTO_N; ++b) {
            for (int row = 0; row < FACTO_N; ++row) {
                fe_t acc = 0;
                for (int col = 0; col < FACTO_V; ++col) {
                    acc = f_add(acc,
                                f_mul(s[(FACTO_N + row) * FACTO_V + col],
                                      kernel_basis[b * FACTO_V + col]));
                }
                truth_contained &= acc == 0;
            }
        }
    } else {
        truth_contained = 0;
    }

    unsigned char encoded_z[SN_BYTES];
    store_fe_vec(encoded_z, z, FACTO_V);
    unsigned long long sig_len = sig_get_sn_len_bytes();
    unsigned char msg[] = "K2 slice fresh-message verifier control";
    int verify_rc = sig_verify((unsigned char *)pk, sig_get_pk_len_bytes(),
                               encoded_z, sig_len,
                               msg, sizeof msg - 1);

    printf("public_all_zero=%d public_zero=%d jacobian_rank=%d "
           "kernel_dim=%d kernel_equals_true_K2=%d sig_verify_rc=%d\n",
           all_zero, all_zero, rank, kernel_dim, truth_contained, verify_rc);
    return 0;
}

int main(int argc, char **argv)
{
    unsigned char *pk = NULL;
    unsigned char *sk = NULL;
    int rc = generate_key(&pk, &sk);
    if (rc != 0) {
        fprintf(stderr, "key generation failed: %d\n", rc);
        return 2;
    }

    static const uint64_t slice_seed = UINT64_C(0x6b325f736c696365);
    fe_t slice[FACTO_V * SLICE_DIM];
    int attempt = make_slice(slice, slice_seed);
    if (attempt < 0) {
        fprintf(stderr, "slice construction failed\n");
        return 3;
    }

    if (argc >= 2 && strcmp(argv[1], "dump") == 0) {
        rc = dump_slice(pk, sk, slice, attempt);
    } else if (argc >= 2 && strcmp(argv[1], "check") == 0 &&
               argc == 2 + SLICE_DIM) {
        fe_t candidate[SLICE_DIM];
        for (int i = 0; i < SLICE_DIM; ++i) {
            char *end = NULL;
            unsigned long v = strtoul(argv[2 + i], &end, 10);
            if (!end || *end || v >= P) {
                fprintf(stderr, "bad candidate coordinate %d\n", i);
                return 4;
            }
            candidate[i] = (fe_t)v;
        }
        rc = check_candidate(pk, sk, slice, candidate);
    } else {
        fprintf(stderr, "usage: %s dump | check <11 coordinates>\n", argv[0]);
        rc = 5;
    }

    free(sk);
    free(pk);
    return rc == 0 ? 0 : 6;
}
