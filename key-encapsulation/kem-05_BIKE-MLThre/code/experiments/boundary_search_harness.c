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

extern void mlthre_debug_set_id(uint32_t id);

static void init_drbg(uint32_t profile, uint32_t key)
{
    unsigned char seed[48];
    for (uint32_t i = 0; i < sizeof(seed); i++) {
        seed[i] = (unsigned char)(0xa5U ^ (i * 29U) ^
                                  (profile << 7) ^ key);
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

int main(int argc, char **argv)
{
    const uint32_t profile = 128;
    const uint32_t key = argc > 1 ? (uint32_t)strtoul(argv[1], NULL, 10) : 100U;
    const unsigned pk_len = CRYPTO_PUBLICKEYBYTES;
    const unsigned sk_len = CRYPTO_SECRETKEYBYTES;
    const unsigned ct_len = CRYPTO_CIPHERTEXTBYTES;
    const unsigned ss_len = CRYPTO_BYTES;
    const size_t c0_len = ct_len - ss_len;

    unsigned char *pk = calloc(1, pk_len);
    unsigned char *sk = calloc(1, sk_len);
    unsigned char *ct = calloc(1, ct_len);
    unsigned char *chosen = calloc(1, ct_len);
    unsigned char *ss = calloc(1, ss_len);
    unsigned char *ss1 = calloc(1, ss_len);

    init_drbg(profile, key);
    if (crypto_kem_keypair(pk, sk) != 0 || crypto_kem_enc(ct, ss, pk) != 0) {
        return 2;
    }

    printf("variant,key,bit,byte,bit_in_byte,ret,match,ct_fnv1a64,ss_fnv1a64\n");
    for (uint32_t bit = 0; bit < (uint32_t)(c0_len * 8U); bit++) {
        memcpy(chosen, ct, ct_len);
        chosen[bit >> 3] ^= (unsigned char)(1U << (bit & 7U));
        mlthre_debug_set_id(bit);
        const int rc = crypto_kem_dec(ss1, chosen, sk);
        printf("%s,%u,%u,%u,%u,%d,%d,%016" PRIx64 ",%016" PRIx64 "\n",
               VARIANT, key, bit, bit >> 3, bit & 7U, rc,
               rc == 0 && memcmp(ss, ss1, ss_len) == 0,
               hash_bytes(chosen, ct_len), hash_bytes(ss1, ss_len));
    }

    free(ss1);
    free(ss);
    free(chosen);
    free(ct);
    free(sk);
    free(pk);
    return 0;
}
