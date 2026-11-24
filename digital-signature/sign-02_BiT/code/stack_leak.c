#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "SIG_AlgorithmInstance.h"
#include "drng.h"
#include "params.h"
#include "packing.h"
#include "polyvec.h"
#include "symmetric.h"

DRNG_ctx drng_algorithm;

static void stack_sample_s0(polyvecl *v, const uint8_t *seed, uint16_t *nonce) {
    for (int i = 0; i < BIT_L; ++i) poly_sample_S1(&v->vec[i], seed, nonce);
}

static void stack_sample_e(polyveck *v, const uint8_t *seed, uint16_t *nonce) {
    for (int i = 0; i < BIT_K; ++i) poly_sample_S1(&v->vec[i], seed, nonce);
}

int main(void) {
    static unsigned char seed[55], msg[32];
    static unsigned char pk[BIT_PUBLICKEYBYTES], sk[BIT_SECRETKEYBYTES], sig[BIT_SIGNBYTES];
    static unsigned char original_secret_seed[BIT_SEEDBYTES];
    unsigned long long pk_len, sk_len, sig_len;
    for (unsigned i = 0; i < sizeof(seed); ++i) seed[i] = (unsigned char)(i + 1);
    if (init_random_number(&drng_algorithm, seed, sizeof(seed)) != 0) return 2;
    if (sig_keygen(pk, &pk_len, sk, &sk_len) != 0) return 3;
    if (sig_sign(sk, sk_len, msg, sizeof(msg), sig, &sig_len) != 0) return 4;

    for (unsigned i = 0; i < BIT_SEEDBYTES; ++i)
        original_secret_seed[i] = sk[BIT_SEEDBYTES + BIT_POLYVECK_B1_BYTES + i];
    memset(sk, 0, sizeof(sk));
    volatile unsigned char marker;
    const unsigned char *lo = (const unsigned char *)&marker - 262144;
    unsigned matches = 0;
    const unsigned char *leak_location = NULL;
    unsigned char leaked_seed[BIT_SEEDBYTES];
    for (const unsigned char *p = lo; p < (const unsigned char *)&marker; ++p) {
        if (memcmp(p, original_secret_seed, BIT_SEEDBYTES) == 0) {
            for (unsigned i = 0; i < BIT_SEEDBYTES; ++i) leaked_seed[i] = p[i];
            printf("secret_seed match at stack offset %td\n", p - lo);
            matches++;
            leak_location = p;
        }
    }
    printf("matches=%u\n", matches);
    if (!leak_location) return 1;

    unsigned char seed_A[BIT_SEEDBYTES];
    unsigned char tr_sk[BIT_TRBYTES];
    uint16_t nonce = 0;
    polyveck b1_pk, b1_check, b0_check, e_regen, b;
    polyvecl s0_regen;
    polyvecl_ntt s0_ntt;
    poly_matrix_ntt A0_ntt;

    unpack_pk(seed_A, &b1_pk, pk);
    stack_sample_s0(&s0_regen, leaked_seed, &nonce);
    stack_sample_e(&e_regen, leaked_seed, &nonce);
    poly_matrix_expand_ntt(&A0_ntt, seed_A);
    polyvecl_to_ntt(&s0_ntt, &s0_regen);
    poly_matrix_mul_vector_ntt(&b, &A0_ntt, &s0_ntt);
    polyveck_add_eta1(&b, &b, &e_regen);
    polyveck_decompose_b(&b1_check, &b0_check, &b);

    int b1_ok = 1;
    for (int i = 0; i < BIT_K; ++i) {
        for (int j = 0; j < BIT_N; ++j) {
            b1_ok &= b1_check.vec[i].coeffs[j] == b1_pk.vec[i].coeffs[j];
        }
    }
#if BIT_TRBYTES == 32
    bit_h256(tr_sk, pk, BIT_PUBLICKEYBYTES);
#else
    bit_h512(tr_sk, pk, BIT_PUBLICKEYBYTES);
#endif
    pack_sk(sk, seed_A, &b1_pk, leaked_seed, tr_sk, &s0_regen, &e_regen, &b0_check);

    static unsigned char msg2[17];
    for (unsigned i = 0; i < sizeof(msg2); ++i) msg2[i] = (unsigned char)(0xC3 ^ i);
    if (sig_sign(sk, sizeof(sk), msg2, sizeof(msg2), sig, &sig_len) != 0) return 5;
    int recovered_key_signs = sig_verify(pk, sizeof(pk), sig, sig_len, msg2, sizeof(msg2)) == 0;
    printf("leak=%u public_b1=%d recovered_key_signs=%d\n", matches, b1_ok, recovered_key_signs);
    return (matches == 1 && b1_ok && recovered_key_signs) ? 0 : 2;
}
