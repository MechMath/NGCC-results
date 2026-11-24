#define _GNU_SOURCE
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "api.h"
#include "kem.h"
#include "FromNIST/rng.h"

#ifndef VARIANT
#define VARIANT "unknown"
#endif

/* Near-valid, supported-length chosen ciphertexts.  Start with one flipped
 * bit and increase through 32 flips, retaining the original c1 payload. */
enum { KEYS = 64, MUTATIONS = 32 };

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
    const unsigned pk_len = CRYPTO_PUBLICKEYBYTES;
    const unsigned sk_len = CRYPTO_SECRETKEYBYTES;
    const unsigned ct_len = CRYPTO_CIPHERTEXTBYTES;
    const unsigned ss_len = CRYPTO_BYTES;

    unsigned char *pk = calloc(1, pk_len);
    unsigned char *sk = calloc(1, sk_len);
    unsigned char *ct = calloc(1, ct_len);
    unsigned char *chosen = calloc(1, ct_len);
    unsigned char *ss = calloc(1, ss_len);
    unsigned char *ss1 = calloc(1, ss_len);
    if (!pk || !sk || !ct || !chosen || !ss || !ss1) {
        return 2;
    }

    printf("variant,key,mutation,flips,ret,match,ct_fnv1a64,ss_fnv1a64\n");
    for (uint32_t key = 0; key < KEYS; key++) {
        init_drbg(128, key);
        if (crypto_kem_keypair(pk, sk) != 0 ||
            crypto_kem_enc(ct, ss, pk) != 0) {
            return 3;
        }

        for (uint32_t mutation = 0; mutation < MUTATIONS; mutation++) {
            memcpy(chosen, ct, ct_len);
            const uint32_t flips = mutation + 1U;
            for (uint32_t bit = 0; bit < flips; bit++) {
                unsigned char random[4];
                randombytes(random, sizeof(random));
                const uint32_t pos =
                    ((uint32_t)random[0] |
                     ((uint32_t)random[1] << 8) |
                     ((uint32_t)random[2] << 16) |
                     ((uint32_t)random[3] << 24)) % ct_len;
                chosen[pos] ^= (unsigned char)(1U << (bit & 7U));
            }
            const int rc = crypto_kem_dec(ss1, chosen, sk);
            printf("%s,%u,%u,%u,%d,%d,%016" PRIx64 ",%016" PRIx64 "\n",
                   VARIANT, key, mutation, flips, rc,
                   rc == 0 && memcmp(ss, ss1, ss_len) == 0,
                   hash_bytes(chosen, ct_len), hash_bytes(ss1, ss_len));
        }
    }

    free(ss1);
    free(ss);
    free(chosen);
    free(ct);
    free(sk);
    free(pk);
    return 0;
}
