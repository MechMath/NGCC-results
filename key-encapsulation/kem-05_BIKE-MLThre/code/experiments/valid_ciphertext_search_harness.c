#define _GNU_SOURCE
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "api.h"
#include "kem.h"
#include "sampling.h"
#include "sha.h"
#include "gf2x.h"
#include "FromNIST/rng.h"

#ifndef VARIANT
#define VARIANT "unknown"
#endif

enum { KEYS = 64, MESSAGES = 32 };

static ret_t function_h(pad_e_t *e, const m_t *m, const pk_t *pk)
{
    DEFER_CLEANUP(seed_t seed = {0}, seed_cleanup);
#if defined(BIND_PK_AND_M)
    DEFER_CLEANUP(sha_dgst_t dgst = {0}, sha_dgst_cleanup);
    DEFER_CLEANUP(pk_m_bind_t pk_m = {0}, pk_m_bind_cleanup);
    pk_m.pk = *pk;
    pk_m.m = *m;
    GUARD(sha(&dgst, sizeof(pk_m), (uint8_t *)&pk_m));
    bike_memcpy(seed.raw, dgst.u.raw, sizeof(seed));
#else
    (void)pk;
    bike_memcpy(seed.raw, m->raw, sizeof(seed));
#endif
    return generate_error_vector(e, &seed);
}

static ret_t function_l(m_t *out, const pad_e_t *e)
{
    DEFER_CLEANUP(sha_dgst_t dgst = {0}, sha_dgst_cleanup);
    DEFER_CLEANUP(e_t tmp, e_cleanup);
    tmp.val[0] = e->val[0].val;
    tmp.val[1] = e->val[1].val;
    GUARD(sha(&dgst, sizeof(tmp), (uint8_t *)&tmp));
    bike_memcpy(out->raw, dgst.u.raw, sizeof(*out));
    return SUCCESS;
}

static ret_t encrypt(ct_t *ct, const pad_e_t *e, const pk_t *pk,
                     const m_t *m)
{
    pad_r_t p_ct = {0};
    pad_r_t p_pk = {0};
    p_pk.val = *pk;
    gf2x_mod_mul(&p_ct, &e->val[1], &p_pk);
    gf2x_mod_add(&p_ct, &p_ct, &e->val[0]);
    ct->c0 = p_ct.val;
    GUARD(function_l(&ct->c1, e));
    for (size_t i = 0; i < sizeof(*m); i++) {
        ct->c1.raw[i] ^= m->raw[i];
    }
    return SUCCESS;
}

static ret_t function_k(ss_t *out, const m_t *m, const ct_t *ct)
{
    DEFER_CLEANUP(func_k_t tmp, func_k_cleanup);
    DEFER_CLEANUP(sha_dgst_t dgst, sha_dgst_cleanup);
    tmp.m = *m;
    tmp.c0 = ct->c0;
    tmp.c1 = ct->c1;
    GUARD(sha(&dgst, sizeof(tmp), (uint8_t *)&tmp));
    bike_memcpy(out->raw, dgst.u.raw, sizeof(*out));
    return SUCCESS;
}

static void init_drbg(uint32_t profile, uint32_t key)
{
    unsigned char seed[48];
    for (uint32_t i = 0; i < sizeof(seed); i++) {
        seed[i] = (unsigned char)(0x5aU ^ (i * 17U) ^
                                  (profile << 4) ^ key);
    }
    randombytes_init(seed, NULL, 256);
}

static uint64_t hash_bytes(const unsigned char *x, size_t n)
{
    uint64_t h = UINT64_C(1469598103934665603);
    for (size_t i = 0; i < n; i++) {
        h ^= x[i];
        h *= UINT64_C(1099511628211);
    }
    return h;
}

int main(void)
{
    unsigned char *pk_raw = calloc(1, CRYPTO_PUBLICKEYBYTES);
    unsigned char *sk_raw = calloc(1, CRYPTO_SECRETKEYBYTES);
    unsigned char *ct_raw = calloc(1, CRYPTO_CIPHERTEXTBYTES);
    unsigned char *ss_dec = calloc(1, CRYPTO_BYTES);
    if (!pk_raw || !sk_raw || !ct_raw || !ss_dec) {
        return 2;
    }

    printf("variant,key,message,ret,match,ct_fnv1a64,m_fnv1a64,ss_fnv1a64\n");
    for (uint32_t key = 0; key < KEYS; key++) {
        init_drbg(128, key);
        if (crypto_kem_keypair(pk_raw, sk_raw) != 0) {
            return 3;
        }
        pk_t pk = {0};
        bike_memcpy(&pk, pk_raw, sizeof(pk));

        for (uint32_t message = 0; message < MESSAGES; message++) {
            DEFER_CLEANUP(m_t m, m_cleanup);
            DEFER_CLEANUP(pad_e_t e, pad_e_cleanup);
            DEFER_CLEANUP(ct_t ct, ct_cleanup);
            DEFER_CLEANUP(ss_t expected, ss_cleanup);
            randombytes(m.raw, sizeof(m));
            GUARD(function_h(&e, &m, &pk));
            GUARD(encrypt(&ct, &e, &pk, &m));
            GUARD(function_k(&expected, &m, &ct));
            bike_memcpy(ct_raw, &ct, sizeof(ct));
            const int rc = crypto_kem_dec(ss_dec, ct_raw, sk_raw);
            printf("%s,%u,%u,%d,%d,%016" PRIx64 ",%016" PRIx64
                   ",%016" PRIx64 "\n",
                   VARIANT, key, message, rc,
                   rc == 0 && memcmp(ss_dec, expected.raw,
                                     sizeof(expected.raw)) == 0,
                   hash_bytes(ct_raw, CRYPTO_CIPHERTEXTBYTES),
                   hash_bytes(m.raw, sizeof(m)),
                   hash_bytes(ss_dec, CRYPTO_BYTES));
        }
    }
    free(ss_dec);
    free(ct_raw);
    free(sk_raw);
    free(pk_raw);
    return 0;
}
