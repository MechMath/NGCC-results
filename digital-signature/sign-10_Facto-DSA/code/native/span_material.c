#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "drng.h"
#include "SIG_AlgorithmInstance.c"

DRNG_ctx drng_algorithm;

#define SPAN_DIM 13

static void seed_drng(unsigned char seed_byte)
{
    unsigned char seed[64];
    for (size_t i = 0; i < sizeof seed; ++i) {
        seed[i] = (unsigned char)(seed_byte + 17u * i);
    }
    if (init_random_number(&drng_algorithm, seed, sizeof seed) != 0) {
        fprintf(stderr, "init_random_number failed\n");
        exit(2);
    }
}

static void make_message(unsigned char msg[32], int index)
{
    memset(msg, 0, 32);
    snprintf((char *)msg, 32, "FactoDSA-span-message-%02d", index);
}

static void print_hex(FILE *out, const unsigned char *p, size_t n)
{
    for (size_t i = 0; i < n; ++i) {
        fprintf(out, "%02x", p[i]);
    }
}

static int matrix_rank(fe_t *a, int rows, int cols)
{
    int rank = 0;
    for (int col = 0; col < cols && rank < rows; ++col) {
        int pivot = -1;
        for (int r = rank; r < rows; ++r) {
            if (a[(size_t)r * cols + col] != 0) {
                pivot = r;
                break;
            }
        }
        if (pivot < 0) {
            continue;
        }
        if (pivot != rank) {
            for (int c = 0; c < cols; ++c) {
                fe_t t = a[(size_t)rank * cols + c];
                a[(size_t)rank * cols + c] = a[(size_t)pivot * cols + c];
                a[(size_t)pivot * cols + c] = t;
            }
        }
        fe_t inv = f_inv(a[(size_t)rank * cols + col]);
        for (int c = 0; c < cols; ++c) {
            a[(size_t)rank * cols + c] =
                f_mul(a[(size_t)rank * cols + c], inv);
        }
        for (int r = 0; r < rows; ++r) {
            if (r == rank || a[(size_t)r * cols + col] == 0) {
                continue;
            }
            fe_t factor = a[(size_t)r * cols + col];
            for (int c = 0; c < cols; ++c) {
                a[(size_t)r * cols + c] = f_sub(
                    a[(size_t)r * cols + c],
                    f_mul(factor, a[(size_t)rank * cols + c]));
            }
        }
        ++rank;
    }
    return rank;
}

static int initialize_key(unsigned char **pk_out, unsigned char **sk_out,
                          unsigned char seed_byte)
{
    seed_drng(seed_byte);
    unsigned long long pk_len = sig_get_pk_len_bytes();
    unsigned long long sk_len = sig_get_sk_len_bytes();
    unsigned char *pk = calloc((size_t)pk_len, 1);
    unsigned char *sk = calloc((size_t)sk_len, 1);
    if (!pk || !sk) {
        free(pk);
        free(sk);
        return -1;
    }
    if (sig_keygen(pk, &pk_len, sk, &sk_len) != 0) {
        free(pk);
        free(sk);
        return -2;
    }
    *pk_out = pk;
    *sk_out = sk;
    return 0;
}

static int dump_case(const char *path)
{
    unsigned char *pk = NULL;
    unsigned char *sk = NULL;
    if (initialize_key(&pk, &sk, 0x5A) != 0) {
        return 3;
    }

    fe_t span[FACTO_V][SPAN_DIM];
    memset(span, 0, sizeof span);
    for (int j = 0; j < SPAN_DIM; ++j) {
        unsigned char msg[32];
        unsigned char sn[SN_BYTES];
        unsigned long long sn_len = SN_BYTES;
        make_message(msg, j);
        if (sig_sign(sk, sig_get_sk_len_bytes(), msg, sizeof msg,
                     sn, &sn_len) != 0 || sn_len != SN_BYTES) {
            fprintf(stderr, "chosen-message sign %d failed\n", j);
            return 4;
        }
        fe_t z[FACTO_V];
        if (load_fe_vec(z, sn, FACTO_V) != 0) {
            return 5;
        }
        for (int i = 0; i < FACTO_V; ++i) {
            span[i][j] = z[i];
        }
    }

    fe_t rank_input[FACTO_V][SPAN_DIM];
    memcpy(rank_input, span, sizeof rank_input);
    int rank = matrix_rank(&rank_input[0][0], FACTO_V, SPAN_DIM);

    unsigned char heldout[32];
    make_message(heldout, 99);
    const unsigned char *pkh = sk + SK_PKH_OFFSET;
    fe_t target[FACTO_M];
    if (xof_field(pkh, heldout, sizeof heldout, target) != 0) {
        return 6;
    }

    unsigned char ground_truth_sn[SN_BYTES];
    unsigned long long ground_truth_len = SN_BYTES;
    if (sig_sign(sk, sig_get_sk_len_bytes(), heldout, sizeof heldout,
                 ground_truth_sn, &ground_truth_len) != 0) {
        return 7;
    }
    fe_t ground_truth[FACTO_V];
    if (load_fe_vec(ground_truth, ground_truth_sn, FACTO_V) != 0) {
        return 8;
    }

    FILE *out = fopen(path, "w");
    if (!out) {
        return 9;
    }
    fprintf(out, "{\n");
    fprintf(out, "  \"schema\": \"facto-dsa-128-signature-span/v1\",\n");
    fprintf(out, "  \"source_sha256\": \"b76d3aa728cbc3d8e247129d326872a857143aa2e2ed4c8c7daca607f415a698\",\n");
    fprintf(out, "  \"q\": %d,\n", P);
    fprintf(out, "  \"span_dim\": %d,\n", SPAN_DIM);
    fprintf(out, "  \"span_rank\": %d,\n", rank);
    fprintf(out, "  \"pk_hex\": \"");
    print_hex(out, pk, sig_get_pk_len_bytes());
    fprintf(out, "\",\n");
    fprintf(out, "  \"heldout_message_hex\": \"");
    print_hex(out, heldout, sizeof heldout);
    fprintf(out, "\",\n");
    fprintf(out, "  \"target\": [");
    for (int i = 0; i < FACTO_M; ++i) {
        fprintf(out, "%s%d", i ? "," : "", target[i]);
    }
    fprintf(out, "],\n");
    fprintf(out, "  \"span_columns\": [\n");
    for (int j = 0; j < SPAN_DIM; ++j) {
        fprintf(out, "    [");
        for (int i = 0; i < FACTO_V; ++i) {
            fprintf(out, "%s%d", i ? "," : "", span[i][j]);
        }
        fprintf(out, "]%s\n", j + 1 == SPAN_DIM ? "" : ",");
    }
    fprintf(out, "  ],\n");
    fprintf(out, "  \"secret_assisted_control\": [");
    for (int i = 0; i < FACTO_V; ++i) {
        fprintf(out, "%s%d", i ? "," : "", ground_truth[i]);
    }
    fprintf(out, "]\n");
    fprintf(out, "}\n");
    fclose(out);
    printf("span_rank=%d path=%s\n", rank, path);
    free(sk);
    free(pk);
    return rank == SPAN_DIM ? 0 : 10;
}

static int check_candidate(int argc, char **argv)
{
    if (argc != 2 + SPAN_DIM) {
        return 20;
    }
    unsigned char *pk = NULL;
    unsigned char *sk = NULL;
    if (initialize_key(&pk, &sk, 0x5A) != 0) {
        return 21;
    }
    fe_t coeff[SPAN_DIM];
    for (int j = 0; j < SPAN_DIM; ++j) {
        char *end = NULL;
        unsigned long v = strtoul(argv[2 + j], &end, 10);
        if (!end || *end || v >= P) {
            return 22;
        }
        coeff[j] = (fe_t)v;
    }

    fe_t span[FACTO_V][SPAN_DIM];
    memset(span, 0, sizeof span);
    for (int j = 0; j < SPAN_DIM; ++j) {
        unsigned char msg[32];
        unsigned char sn[SN_BYTES];
        unsigned long long sn_len = SN_BYTES;
        make_message(msg, j);
        if (sig_sign(sk, sig_get_sk_len_bytes(), msg, sizeof msg,
                     sn, &sn_len) != 0) {
            return 23;
        }
        fe_t z[FACTO_V];
        load_fe_vec(z, sn, FACTO_V);
        for (int i = 0; i < FACTO_V; ++i) {
            span[i][j] = z[i];
        }
    }

    fe_t z[FACTO_V];
    for (int i = 0; i < FACTO_V; ++i) {
        fe_t acc = 0;
        for (int j = 0; j < SPAN_DIM; ++j) {
            acc = f_add(acc, f_mul(span[i][j], coeff[j]));
        }
        z[i] = acc;
    }
    unsigned char sn[SN_BYTES];
    store_fe_vec(sn, z, FACTO_V);

    unsigned char heldout[32];
    make_message(heldout, 99);
    fe_t pz[FACTO_M];
    fe_t target[FACTO_M];
    eval_public_key(pk, z, pz);
    xof_field(sk + SK_PKH_OFFSET, heldout, sizeof heldout, target);
    int public_match = 1;
    for (int i = 0; i < FACTO_M; ++i) {
        public_match &= pz[i] == target[i];
    }
    int verify_rc = sig_verify(pk, sig_get_pk_len_bytes(), sn, SN_BYTES,
                               heldout, sizeof heldout);

    unsigned char *other_pk = NULL;
    unsigned char *other_sk = NULL;
    initialize_key(&other_pk, &other_sk, 0xC3);
    int changed_key_rc = sig_verify(other_pk, sig_get_pk_len_bytes(),
                                    sn, SN_BYTES, heldout, sizeof heldout);
    unsigned char different_message[32];
    make_message(different_message, 98);
    int changed_message_rc = sig_verify(pk, sig_get_pk_len_bytes(),
                                        sn, SN_BYTES, different_message,
                                        sizeof different_message);
    printf("public_match=%d sig_verify_rc=%d changed_key_rc=%d "
           "changed_message_rc=%d\n",
           public_match, verify_rc, changed_key_rc, changed_message_rc);
    free(other_sk);
    free(other_pk);
    free(sk);
    free(pk);
    return verify_rc == 0 ? 0 : 30;
}

static int check_positive_control(void)
{
    unsigned char *pk = NULL;
    unsigned char *sk = NULL;
    if (initialize_key(&pk, &sk, 0x5A) != 0) {
        return 40;
    }
    unsigned char heldout[32];
    unsigned char sn[SN_BYTES];
    unsigned long long sn_len = SN_BYTES;
    make_message(heldout, 99);
    if (sig_sign(sk, sig_get_sk_len_bytes(), heldout, sizeof heldout,
                 sn, &sn_len) != 0) {
        return 41;
    }
    int verify_rc = sig_verify(pk, sig_get_pk_len_bytes(), sn, SN_BYTES,
                               heldout, sizeof heldout);
    printf("groundtruth_sig_verify_rc=%d\n", verify_rc);
    free(sk);
    free(pk);
    return verify_rc == 0 ? 0 : 42;
}

int main(int argc, char **argv)
{
    if (argc == 3 && strcmp(argv[1], "dump") == 0) {
        return dump_case(argv[2]);
    }
    if (argc == 2 && strcmp(argv[1], "groundtruth") == 0) {
        return check_positive_control();
    }
    if (argc >= 2 && strcmp(argv[1], "check") == 0) {
        return check_candidate(argc, argv);
    }
    fprintf(stderr,
            "usage: %s dump <path> | groundtruth | check <13 coefficients>\n",
            argv[0]);
    return 1;
}
