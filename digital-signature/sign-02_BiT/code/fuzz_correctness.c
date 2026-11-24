#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "SIG_AlgorithmInstance.h"
#include "drng.h"
#include "params.h"

DRNG_ctx drng_algorithm;

int main(int argc, char **argv) {
    const unsigned trials = argc > 1 ? (unsigned)strtoul(argv[1], NULL, 10) : 100;
    unsigned char seed[55];
    unsigned char msg[513];
    unsigned char pk[BIT_PUBLICKEYBYTES];
    unsigned char sk[BIT_SECRETKEYBYTES];
    unsigned char sig[BIT_SIGNBYTES];
    unsigned long long pk_len = 0, sk_len = 0, sig_len = 0;

    for (unsigned t = 0; t < trials; ++t) {
        for (unsigned i = 0; i < sizeof(seed); ++i)
            seed[i] = (unsigned char)(t * 131u + i * 17u + 0xA5u);
        size_t mlen = (t * 73u) % (sizeof(msg) + 1u);
        for (size_t i = 0; i < mlen; ++i)
            msg[i] = (unsigned char)(t * 29u + i * 191u);

        if (init_random_number(&drng_algorithm, seed, sizeof(seed)) != 0) return 10;
        if (sig_keygen(pk, &pk_len, sk, &sk_len) != 0) return 11;
        if (sig_sign(sk, sk_len, msg, mlen, sig, &sig_len) != 0) {
            fprintf(stderr, "sign failure t=%u mlen=%zu\n", t, mlen);
            return 12;
        }
        if (sig_verify(pk, pk_len, sig, sig_len, msg, mlen) != 0) {
            fprintf(stderr, "verify failure t=%u mlen=%zu\n", t, mlen);
            return 13;
        }
    }
    printf("PASS trials=%u\n", trials);
    return 0;
}
