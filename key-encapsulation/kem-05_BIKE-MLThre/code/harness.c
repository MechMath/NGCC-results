#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "api.h"
#include "kem.h"
#include "FromNIST/rng.h"
#if defined(HARNESS_OPTIMIZED)
#include "cpu_features.h"
#endif

static uint64_t splitmix64(uint64_t *state)
{
    uint64_t z = (*state += UINT64_C(0x9e3779b97f4a7c15));
    z = (z ^ (z >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
    z = (z ^ (z >> 27)) * UINT64_C(0x94d049bb133111eb);
    return z ^ (z >> 31);
}

static void mutate(uint8_t *dst, const uint8_t *src, size_t len, uint64_t seed)
{
    uint64_t state = seed;
    size_t changes = 1 + (size_t)(splitmix64(&state) % 32);
    memcpy(dst, src, len);
    for (size_t i = 0; i < changes; i++) {
        size_t pos = (size_t)(splitmix64(&state) % len);
        dst[pos] ^= (uint8_t)(1U << (splitmix64(&state) & 7U));
    }
}

int main(int argc, char **argv)
{
    const unsigned iterations = (argc > 1) ? (unsigned)strtoul(argv[1], NULL, 10) : 64;
    uint8_t entropy[48];
    uint8_t personalization[48] = {0};
    uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[CRYPTO_SECRETKEYBYTES];
    uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
    uint8_t bad_ct[CRYPTO_CIPHERTEXTBYTES];
    uint8_t ss_enc[CRYPTO_BYTES];
    uint8_t ss_dec[CRYPTO_BYTES];

    for (size_t i = 0; i < sizeof(entropy); i++) {
        entropy[i] = (uint8_t)i;
    }
#if defined(HARNESS_OPTIMIZED)
    cpu_features_init();
#endif
    randombytes_init(entropy, personalization, 256);

    if (crypto_kem_keypair(pk, sk) != 0) {
        fprintf(stderr, "keypair failed\n");
        return 2;
    }
    if (crypto_kem_enc(ct, ss_enc, pk) != 0) {
        fprintf(stderr, "encapsulation failed\n");
        return 3;
    }
    if (crypto_kem_dec(ss_dec, ct, sk) != 0) {
        fprintf(stderr, "valid decapsulation returned failure\n");
        return 4;
    }
    if (memcmp(ss_enc, ss_dec, CRYPTO_BYTES) != 0) {
        fprintf(stderr, "valid decapsulation shared-secret mismatch\n");
        return 5;
    }
    printf("PASS valid pk=%zu sk=%zu ct=%zu ss=%zu\n",
           (size_t)CRYPTO_PUBLICKEYBYTES, (size_t)CRYPTO_SECRETKEYBYTES,
           (size_t)CRYPTO_CIPHERTEXTBYTES, (size_t)CRYPTO_BYTES);

    memset(bad_ct, 0, sizeof(bad_ct));
    if (crypto_kem_dec(ss_dec, bad_ct, sk) != 0) {
        fprintf(stderr, "zero ciphertext returned failure\n");
        return 6;
    }
    printf("PASS zero_ciphertext\n");

    memset(bad_ct, 0xff, sizeof(bad_ct));
    if (crypto_kem_dec(ss_dec, bad_ct, sk) != 0) {
        fprintf(stderr, "all-ones ciphertext returned failure\n");
        return 7;
    }
    printf("PASS all_ones_ciphertext\n");

    for (unsigned i = 0; i < iterations; i++) {
        mutate(bad_ct, ct, sizeof(bad_ct), UINT64_C(0x434b4b5332303236) + i);
        if (crypto_kem_dec(ss_dec, bad_ct, sk) != 0) {
            fprintf(stderr, "mutation %u returned failure\n", i);
            return 8;
        }
    }
    printf("PASS bit_mutations=%u\n", iterations);
    return 0;
}
