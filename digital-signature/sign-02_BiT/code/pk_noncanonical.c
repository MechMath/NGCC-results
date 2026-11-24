#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "drng.h"
#include "packing.h"
#include "params.h"
#include "sign.h"
#include "symmetric.h"

#define B1_BASE 1681ULL
#define B1_BASE4 (B1_BASE * B1_BASE * B1_BASE * B1_BASE)

DRNG_ctx drng_algorithm;

static uint64_t get43(const uint8_t *p, int block)
{
    uint64_t v = 0;
    for (int j = 0; j < 43; ++j) {
        int bit = 43 * block + j;
        v |= (uint64_t)((p[bit >> 3] >> (bit & 7)) & 1U) << j;
    }
    return v;
}

static void put43(uint8_t *p, int block, uint64_t v)
{
    for (int j = 0; j < 43; ++j) {
        int bit = 43 * block + j;
        uint8_t mask = (uint8_t)(1U << (bit & 7));
        if ((v >> j) & 1U)
            p[bit >> 3] |= mask;
        else
            p[bit >> 3] &= (uint8_t)~mask;
    }
}

static int b1_equal(const polyveck *a, const polyveck *b)
{
    for (int i = 0; i < BIT_K; ++i)
        for (int j = 0; j < BIT_N; ++j)
            if (a->vec[i].coeffs[j] != b->vec[i].coeffs[j]) {
                printf("first decoded difference poly=%d coeff=%d old=%d new=%d\n",
                       i, j, a->vec[i].coeffs[j], b->vec[i].coeffs[j]);
                return 0;
            }
    return 1;
}

int main(void)
{
    uint8_t seed[64] = {0};
    uint8_t pk[BIT_PUBLICKEYBYTES], sk[BIT_SECRETKEYBYTES];
    uint8_t sig[BIT_SIGNBYTES], sig2[BIT_SIGNBYTES], sig3[BIT_SIGNBYTES];
    uint8_t msg[] = "non-canonical public key test";
    unsigned long long pklen = sizeof(pk), sklen = sizeof(sk);
    unsigned long long siglen = sizeof(sig), sig2len = sizeof(sig2);
    unsigned long long sig3len = sizeof(sig3);
    polyveck b1a, b1b;
    uint8_t seedA[BIT_SEEDBYTES];

    memcpy(seed, "BiT public-key encoding test seed", 33);
    if (init_random_number(&drng_algorithm, seed, sizeof(seed)) != 0) return 2;
    if (bit_sig_keygen(pk, &pklen, sk, &sklen) != 0) return 3;
    if (bit_sig_sign(sk, sklen, msg, sizeof(msg) - 1, sig, &siglen) != 0) return 4;
    int orig_verify = bit_sig_verify(sig, siglen, msg, sizeof(msg) - 1, pk, pklen);

    unpack_pk(seedA, &b1a, pk);
    uint8_t pk2[BIT_PUBLICKEYBYTES];
    memcpy(pk2, pk, sizeof(pk));
    int block = -1;
    for (int i = 0; i < (int)(BIT_POLYVECK_B1_BYTES * 8 / 43); ++i) {
        uint64_t v = get43(pk2 + BIT_SEEDBYTES, i);
        if (v + B1_BASE4 < (1ULL << 43)) {
            put43(pk2 + BIT_SEEDBYTES, i, v + B1_BASE4);
            block = i;
            break;
        }
    }
    if (block < 0) return 5;

    unpack_pk(seedA, &b1b, pk2);
    int same_b1 = b1_equal(&b1a, &b1b);
    int changed_bytes = 0;
    for (size_t i = 0; i < sizeof(pk); ++i)
        changed_bytes += pk[i] != pk2[i];
    int sig_under_pk2 = bit_sig_verify(sig, siglen, msg, sizeof(msg) - 1, pk2, pklen);

    if (bit_sig_sign(sk, sklen, msg, sizeof(msg) - 1, sig2, &sig2len) != 0) return 6;
    int sig2_under_pk = bit_sig_verify(sig2, sig2len, msg, sizeof(msg) - 1, pk, pklen);
    int sig2_under_pk2 = bit_sig_verify(sig2, sig2len, msg, sizeof(msg) - 1, pk2, pklen);

    uint8_t sk2[BIT_SECRETKEYBYTES];
    memcpy(sk2, sk, sizeof(sk2));
    uint8_t *tr2 = sk2 + BIT_SEEDBYTES + BIT_POLYVECK_B1_BYTES + BIT_SEEDBYTES;
    bit_h256(tr2, pk2, pklen);
    if (bit_sig_sign(sk2, sklen, msg, sizeof(msg) - 1, sig3, &sig3len) != 0) return 7;
    int sig3_under_pk2 = bit_sig_verify(sig3, sig3len, msg, sizeof(msg) - 1, pk2, pklen);

    printf("block=%d encoded=0x%llx changed_bytes=%d same_decoded_b1=%d\n",
           block, (unsigned long long)get43(pk2 + BIT_SEEDBYTES, block),
           changed_bytes, same_b1);
    printf("original_pk_verify=%d mutated_pk_verify=%d second_original=%d second_mutated=%d\n",
           orig_verify, sig_under_pk2, sig2_under_pk, sig2_under_pk2);
    printf("rebound_tr_signature_under_mutated_pk=%d\n", sig3_under_pk2);
    return (same_b1 && orig_verify == 0 && sig_under_pk2 == -1 &&
            sig2_under_pk == 0 && sig2_under_pk2 == -1 &&
            sig3_under_pk2 == 0) ? 0 : 1;
}
