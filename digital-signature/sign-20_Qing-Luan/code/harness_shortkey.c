#include "api.h"
#include "SIG_AlgorithmInstance.h"
#include "drng.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

DRNG_ctx drng_algorithm;

int main(int argc, char **argv)
{
    unsigned char pk[CRYPTO_PUBLICKEYBYTES], sk[CRYPTO_SECRETKEYBYTES];
    unsigned char sig[CRYPTO_BYTES], msg[] = "short-length key";
    unsigned char seed[64];
    size_t siglen = 0;
    unsigned long long siglen_ull = 0;
    if (argc != 2) return 2;
    for (size_t i = 0; i < sizeof(seed); i++) seed[i] = (unsigned char)i;
    if (init_random_number(&drng_algorithm, seed, sizeof(seed)) != 0) return 2;
    if (crypto_sign_keypair(pk, sk) ||
        crypto_sign_signature(sig, &siglen, msg, sizeof(msg)-1, sk)) return 2;

    if (strcmp(argv[1], "pk") == 0) {
        unsigned char *short_pk = malloc(1);
        short_pk[0] = pk[0];
        printf("calling sig_verify with pk_len=1 on a 1-byte allocation\n");
        fflush(stdout);
        return sig_verify(short_pk, 1, sig, siglen, msg, sizeof(msg)-1);
    }
    if (strcmp(argv[1], "sk") == 0) {
        unsigned char *short_sk = malloc(1);
        short_sk[0] = sk[0];
        printf("calling sig_sign with sk_len=1 on a 1-byte allocation\n");
        fflush(stdout);
        return sig_sign(short_sk, 1, msg, sizeof(msg)-1, sig, &siglen_ull);
    }
    return 2;
}
