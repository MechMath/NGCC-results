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

enum { KEYS = 16, CLASSES = 6 };

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
    const uint32_t profile =
#if defined(BIKE_SECURITY_256) || SECURITY_BITS == 256
        256;
#else
        128;
#endif
    unsigned char *pk = calloc(1, pk_len);
    unsigned char *sk = calloc(1, sk_len);
    unsigned char *ct = calloc(1, ct_len);
    unsigned char *ss = calloc(1, ss_len);
    unsigned char *ss1 = calloc(1, ss_len);
    unsigned char *choices = calloc(CLASSES, ct_len);

    printf("variant,profile,key,ct_class,ret,match,ct_fnv1a64,ss_fnv1a64\n");
    for (uint32_t key = 0; key < KEYS; key++) {
        init_drbg(profile, key);
        if (crypto_kem_keypair(pk, sk) != 0 ||
            crypto_kem_enc(ct, ss, pk) != 0) {
            return 2;
        }
        memcpy(choices + 0 * ct_len, ct, ct_len);
        memset(choices + 1 * ct_len, 0, ct_len);
        memcpy(choices + 2 * ct_len, ct, ct_len);
        randombytes(choices + 2 * ct_len, ct_len);
        memcpy(choices + 3 * ct_len, ct, ct_len);
        randombytes(choices + 3 * ct_len + (ct_len - ss_len), ss_len);
        memcpy(choices + 4 * ct_len, ct, ct_len);
        choices[4 * ct_len + (key % (ct_len - ss_len))] ^= 1U;
        memcpy(choices + 5 * ct_len, ct, ct_len);
        randombytes(choices + 5 * ct_len, ct_len);

        for (uint32_t cls = 0; cls < CLASSES; cls++) {
            const unsigned char *chosen = choices + cls * ct_len;
            const int rc = crypto_kem_dec(ss1, chosen, sk);
            printf("%s,%u,%u,%u,%d,%d,%016" PRIx64 ",%016" PRIx64 "\n",
                   VARIANT, profile, key, cls, rc,
                   rc == 0 && memcmp(ss, ss1, ss_len) == 0,
                   hash_bytes(chosen, ct_len), hash_bytes(ss1, ss_len));
        }
    }
    free(choices);
    free(ss1);
    free(ss);
    free(ct);
    free(sk);
    free(pk);
    return 0;
}
