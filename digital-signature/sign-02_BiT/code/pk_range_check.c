#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "drng.h"
#include "packing.h"
#include "params.h"
#include "sign.h"

DRNG_ctx drng_algorithm;

static uint32_t get_bits(const uint8_t *p, int bitpos)
{
    uint32_t v = 0;
    for (int j = 0; j < BIT_POLY_B1_BITS; ++j) {
        int bit = bitpos + j;
        v |= (uint32_t)((p[bit >> 3] >> (bit & 7)) & 1U) << j;
    }
    return v;
}

static void put_bits(uint8_t *p, int bitpos, uint32_t v)
{
    for (int j = 0; j < BIT_POLY_B1_BITS; ++j) {
        int bit = bitpos + j;
        uint8_t mask = (uint8_t)(1U << (bit & 7));
        if ((v >> j) & 1U)
            p[bit >> 3] |= mask;
        else
            p[bit >> 3] &= (uint8_t)~mask;
    }
}

int main(void)
{
    uint8_t seed[55] = {0};
    uint8_t pk[BIT_PUBLICKEYBYTES], pk2[BIT_PUBLICKEYBYTES];
    uint8_t sk[BIT_SECRETKEYBYTES], sig[BIT_SIGNBYTES];
    uint8_t msg[] = "public key range check";
    unsigned long long pklen = sizeof(pk), sklen = sizeof(sk), siglen = sizeof(sig);
    uint8_t seedA[BIT_SEEDBYTES];
    polyveck b1;
    uint32_t invalid = (1U << BIT_POLY_B1_BITS) - 1U;

    for (unsigned i = 0; i < sizeof(seed); ++i) seed[i] = (uint8_t)(i + 1);
    if (init_random_number(&drng_algorithm, seed, sizeof(seed)) != 0) return 2;
    if (bit_sig_keygen(pk, &pklen, sk, &sklen) != 0) return 3;
    if (bit_sig_sign(sk, sklen, msg, sizeof(msg) - 1, sig, &siglen) != 0) return 4;
    int original = bit_sig_verify(sig, siglen, msg, sizeof(msg) - 1, pk, pklen);

    memcpy(pk2, pk, sizeof(pk));
    put_bits(pk2 + BIT_SEEDBYTES, 0, invalid);
    unpack_pk(seedA, &b1, pk2);
    int mutated = bit_sig_verify(sig, siglen, msg, sizeof(msg) - 1, pk2, pklen);

    printf("bits=%d invalid=%u decoded=%d original_verify=%d mutated_verify=%d\n",
           BIT_POLY_B1_BITS, invalid, b1.vec[0].coeffs[0], original, mutated);
    return (b1.vec[0].coeffs[0] == (int16_t)invalid &&
            original == 0 && mutated == -1) ? 0 : 1;
}
