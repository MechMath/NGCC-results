#include <stdio.h>

#include "api.h"

void randombytes(unsigned char *out, unsigned long long outlen)
{
    (void)out;
    (void)outlen;
}

int main(int argc, char **argv)
{
    unsigned char seed[CRYPTO_SEEDBYTES];
    unsigned char pk[CRYPTO_PUBLICKEYBYTES];
    unsigned char sk[CRYPTO_SECRETKEYBYTES];
    FILE *f;
    size_t i;

    if (argc != 2) {
        return 2;
    }
    f = fopen(argv[1], "rb");
    if (f == NULL || fread(seed, 1, sizeof(seed), f) != sizeof(seed)) {
        return 3;
    }
    fclose(f);

    if (crypto_sign_seed_keypair(pk, sk, seed) != 0) {
        return 4;
    }
    for (i = 0; i < sizeof(pk); i++) {
        printf("%02X", pk[i]);
    }
    printf("\n");
    return 0;
}
