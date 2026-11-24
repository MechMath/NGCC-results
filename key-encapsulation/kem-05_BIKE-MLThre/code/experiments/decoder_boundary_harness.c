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

enum { KEYS = 8, SAMPLES = 16, FIRST_WEIGHT = 125, LAST_WEIGHT = 145 };

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
    for (size_t i = 0; i < sizeof(*m); i++)
        ct->c1.raw[i] ^= m->raw[i];
    return SUCCESS;
}

static void init_drbg(uint32_t key)
{
    unsigned char seed[48];
    for (uint32_t i = 0; i < sizeof(seed); i++)
        seed[i] = (unsigned char)(0x6dU ^ (i * 29U) ^ key);
    randombytes_init(seed, NULL, 256);
}

static uint64_t next64(uint32_t *s)
{
    uint64_t x = *s;
    x ^= x << 13; x ^= x >> 7; x ^= x << 17;
    *s = (uint32_t)x;
    return x;
}

static void set_weight(r_t *r, uint32_t weight, uint32_t *state)
{
    bike_memset(r->raw, 0, sizeof(r->raw));
    for (uint32_t n = 0; n < weight;) {
        uint32_t pos = (uint32_t)(next64(state) % R_BITS);
        uint32_t byte = pos / 8;
        uint8_t mask = (uint8_t)(1U << (pos % 8));
        if (!(r->raw[byte] & mask)) {
            r->raw[byte] |= mask;
            n++;
        }
    }
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
    unsigned char *ss_native = calloc(1, CRYPTO_BYTES);
    if (!pk_raw || !sk_raw || !ct_raw || !ss_dec || !ss_native) return 2;

    printf("variant,key,control_rc,control_match,weight,sample,ret,match,ct_fnv1a64,ss_fnv1a64\n");
    for (uint32_t key = 0; key < KEYS; key++) {
        init_drbg(key);
        if (crypto_kem_keypair(pk_raw, sk_raw) != 0) return 3;
        const int crc = crypto_kem_enc(ct_raw, ss_native, pk_raw);
        const int drc = crypto_kem_dec(ss_dec, ct_raw, sk_raw);
        printf("%s,%u,%d,%d,control,0,%d,%d,0,0\n", VARIANT, key, crc,
               crc == 0 && drc == 0 && !memcmp(ss_native, ss_dec, CRYPTO_BYTES),
               drc);

        pk_t pk = {0};
        bike_memcpy(&pk, pk_raw, sizeof(pk));
        for (uint32_t weight = FIRST_WEIGHT; weight <= LAST_WEIGHT; weight++) {
            for (uint32_t sample = 0; sample < SAMPLES; sample++) {
                DEFER_CLEANUP(m_t m, m_cleanup);
                DEFER_CLEANUP(pad_e_t e, pad_e_cleanup);
                DEFER_CLEANUP(ct_t ct, ct_cleanup);
                DEFER_CLEANUP(ss_t expected, ss_cleanup);
                uint32_t state = UINT32_C(0x9e3779b9) ^
                                 (key * UINT32_C(0x85ebca6b)) ^
                                 (weight * UINT32_C(0xc2b2ae35)) ^
                                 (sample * UINT32_C(0x27d4eb2d));
                for (uint32_t i = 0; i < sizeof(m.raw); i++)
                    m.raw[i] = (uint8_t)(next64(&state) >> 24);
                set_weight(&e.val[0].val, weight, &state);
                set_weight(&e.val[1].val, weight, &state);
                GUARD(encrypt(&ct, &e, &pk, &m));
                GUARD(function_k(&expected, &m, &ct));
                bike_memcpy(ct_raw, &ct, sizeof(ct));
                const int rc = crypto_kem_dec(ss_dec, ct_raw, sk_raw);
                const int match = rc == 0 &&
                    !memcmp(ss_dec, expected.raw, sizeof(expected.raw));
                printf("%s,%u,0,1,%u,%u,%d,%d,%016" PRIx64 ",%016" PRIx64 "\n",
                       VARIANT, key, weight, sample, rc, match,
                       hash_bytes(ct_raw, CRYPTO_CIPHERTEXTBYTES),
                       hash_bytes(ss_dec, CRYPTO_BYTES));
            }
        }
    }
    free(ss_native); free(ss_dec); free(ct_raw); free(sk_raw); free(pk_raw);
    return 0;
}
