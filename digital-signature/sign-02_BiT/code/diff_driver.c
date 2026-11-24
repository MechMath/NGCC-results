#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "SIG_AlgorithmInstance.h"
#include "drng.h"
#include "params.h"

DRNG_ctx drng_algorithm;

int main(int argc, char **argv) {
    if (argc != 3) return 2;
    const unsigned trials = (unsigned)strtoul(argv[1], NULL, 10);
    FILE *out = fopen(argv[2], "wb");
    if (!out) return 3;
    unsigned char seed[55], msg[513];
    unsigned char pk[BIT_PUBLICKEYBYTES], sk[BIT_SECRETKEYBYTES], sig[BIT_SIGNBYTES];
    unsigned long long pk_len, sk_len, sig_len;

    for (unsigned t = 0; t < trials; ++t) {
        for (unsigned i = 0; i < sizeof(seed); ++i)
            seed[i] = (unsigned char)(t * 131u + i * 17u + 0xA5u);
        size_t mlen = (t * 73u) % (sizeof(msg) + 1u);
        for (size_t i = 0; i < mlen; ++i)
            msg[i] = (unsigned char)(t * 29u + i * 191u);
        if (init_random_number(&drng_algorithm, seed, sizeof(seed)) != 0) return 4;
        if (sig_keygen(pk, &pk_len, sk, &sk_len) != 0) return 5;
        if (sig_sign(sk, sk_len, msg, mlen, sig, &sig_len) != 0) return 6;
        if (sig_verify(pk, pk_len, sig, sig_len, msg, mlen) != 0) return 7;
        fwrite(&mlen, sizeof(mlen), 1, out);
        fwrite(pk, 1, sizeof(pk), out);
        fwrite(sk, 1, sizeof(sk), out);
        fwrite(sig, 1, sizeof(sig), out);
        fwrite(msg, 1, mlen, out);
    }
    return fclose(out) != 0 ? 8 : 0;
}
