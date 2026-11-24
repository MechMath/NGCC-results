#include <stdio.h>
#include <string.h>

#include "SIG_AlgorithmInstance.h"
#include "drng.h"
#include "params.h"

DRNG_ctx drng_algorithm;

static size_t differing_bytes(const unsigned char *a, const unsigned char *b,
                              size_t len) {
    size_t count = 0;
    for (size_t i = 0; i < len; i++) {
        count += a[i] != b[i];
    }
    return count;
}

int main(int argc, char **argv) {
    const char *outdir = (argc > 1) ? argv[1] : ".";
    const unsigned char msg[] =
        "BiT final-group hint alias experiment.";
    unsigned char seed[55];
    unsigned char pk[BIT_PUBLICKEYBYTES];
    unsigned char sk[BIT_SECRETKEYBYTES];
    unsigned char sig[BIT_SIGNBYTES];
    unsigned long long pk_len = 0;
    unsigned long long sk_len = 0;
    unsigned long long sig_len = 0;
    unsigned int accepted = 0;
    unsigned int tested = 0;
    unsigned int negative_ok = 1;
    const size_t hint_offset = (size_t)BIT_SIGNBYTES - BIT_POLYVECK_H_BYTES;

    (void)outdir;
    for (size_t i = 0; i < sizeof(seed); i++) {
        seed[i] = (unsigned char)(0x5AU + 13U * 512U + 7U * 204U + i);
    }
    if (init_random_number(&drng_algorithm, seed, sizeof(seed)) != 0) return 2;
    if (sig_keygen(pk, &pk_len, sk, &sk_len) != 0) return 3;
    if (sig_sign(sk, sk_len, (unsigned char *)msg, sizeof(msg) - 1,
                 sig, &sig_len) != 0) return 4;
    if (sig_verify(pk, pk_len, sig, sig_len,
                   (unsigned char *)msg, sizeof(msg) - 1) != 0) return 5;
    if (sig_len != BIT_SIGNBYTES || pk_len != BIT_PUBLICKEYBYTES) return 6;

    printf("algorithm=%s\n", ALGORITHM_INSTANCE);
    printf("pk_len=%llu sk_len=%llu sig_len=%llu\n", pk_len, sk_len, sig_len);
    printf("hint_offset=%zu hint_bytes=%d\n",
           hint_offset, BIT_POLYVECK_H_BYTES);

    for (int r = 0; r < BIT_K; r++) {
        size_t tail = hint_offset + (size_t)(r + 1) * BIT_POLY_H_BASE3_BYTES - 1;
        unsigned int d = (unsigned int)sig[tail] % 81U;
        unsigned int local_accepted = 0;
        unsigned int local_tested = 0;

        printf("tail=%d offset=%zu old=%u mod81=%u",
               r, tail, (unsigned int)sig[tail], d);
        for (int j = 0; j < 3; j++) {
            unsigned int candidate = d + (unsigned int)j * 81U;
            unsigned char mutant[BIT_SIGNBYTES];
            if (candidate == (unsigned int)sig[tail]) continue;
            memcpy(mutant, sig, (size_t)sig_len);
            mutant[tail] = (unsigned char)candidate;
            local_tested++;
            tested++;
            if (sig_verify(pk, pk_len, mutant, sig_len,
                           (unsigned char *)msg, sizeof(msg) - 1) == 0 &&
                differing_bytes(sig, mutant, (size_t)sig_len) == 1) {
                local_accepted++;
                accepted++;
            }
        }

        {
            unsigned char negative[BIT_SIGNBYTES];
            memcpy(negative, sig, (size_t)sig_len);
            negative[tail] = (unsigned char)(sig[tail] + 1U);
            if (sig_verify(pk, pk_len, negative, sig_len,
                           (unsigned char *)msg, sizeof(msg) - 1) == 0) {
                negative_ok = 0;
            }
        }
        printf(" tested=%u accepted=%u\n", local_tested, local_accepted);
    }

    printf("total_tested=%u total_accepted=%u plus_one_controls_all_rejected=%u\n",
           tested, accepted, negative_ok);
    return tested == 6 && accepted == 6 && negative_ok ? 0 : 1;
}
