#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "drng.h"

/*
 * Include the untouched submitted translation unit so that the probe can use
 * its static coefficient ordering and secret-key layout without modifying it.
 */
#include "SIG_AlgorithmInstance.c"

DRNG_ctx drng_algorithm;

static int matrix_rank_mod(fe_t *a, int rows, int cols)
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
                fe_t t = a[rank * cols + c];
                a[rank * cols + c] = a[pivot * cols + c];
                a[pivot * cols + c] = t;
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

int main(void)
{
    unsigned char seed[64];
    for (size_t i = 0; i < sizeof seed; ++i) {
        seed[i] = (unsigned char)(0x5Au + 17u * i);
    }
    if (init_random_number(&drng_algorithm, seed, sizeof seed) != 0) {
        return 2;
    }

    unsigned long long pk_len = sig_get_pk_len_bytes();
    unsigned long long sk_len = sig_get_sk_len_bytes();
    unsigned char *pk = calloc((size_t)pk_len, 1);
    unsigned char *sk = calloc((size_t)sk_len, 1);
    if (!pk || !sk) {
        return 3;
    }
    int rc = sig_keygen(pk, &pk_len, sk, &sk_len);
    if (rc != 0) {
        return 4;
    }

    fe_t sinv[SK_SINV_ELEMS];
    if (sk_load_fe_array(sk, SK_SINV_OFFSET, sinv, SK_SINV_ELEMS) != 0) {
        return 5;
    }

    fe_t v[FACTO_V] = {0};
    fe_t p_out[FACTO_M] = {0};
    fe_t jac[FACTO_M * FACTO_V] = {0};
    int good_rank = -1;
    int bad_rank = -1;

    for (int item = 0; item < 8; ++item) {
        fe_t y[FACTO_N] = {0};
        y[item] = (fe_t)(item + 1);
        fe_t hidden[FACTO_V] = {0};
        for (int i = 0; i < FACTO_N; ++i) {
            hidden[i] = y[i];
        }
        matrix_vec_mul(sinv, hidden, v, FACTO_V, FACTO_V);
        if (eval_public_key(pk, v, p_out) != 0) {
            return 6;
        }
        int zero = 1;
        for (int r = 0; r < FACTO_M; ++r) {
            zero &= (p_out[r] == 0);
        }
        memset(jac, 0, sizeof jac);
        if (public_jacobian(pk, v, jac) != 0) {
            return 7;
        }
        int rank = matrix_rank_mod(jac, FACTO_M, FACTO_V);
        printf("K2_basis=%d public_zero=%d jacobian_rank=%d\n",
               item, zero, rank);
        if (rank == FACTO_N && good_rank < 0) {
            good_rank = item;
        }
    }

    fe_t ctrl[FACTO_V] = {0};
    for (int i = 0; i < FACTO_V; ++i) {
        ctrl[i] = (fe_t)(101 + i);
    }
    memset(jac, 0, sizeof jac);
    if (public_jacobian(pk, ctrl, jac) != 0) {
        return 7;
    }
    bad_rank = matrix_rank_mod(jac, FACTO_M, FACTO_V);
    printf("random_control jacobian_rank=%d\n", bad_rank);

    free(sk);
    free(pk);
    return good_rank >= 0 ? 0 : 8;
}
