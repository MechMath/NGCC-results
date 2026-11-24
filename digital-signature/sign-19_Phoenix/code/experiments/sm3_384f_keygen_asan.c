#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "api.h"

int main(void)
{
    unsigned char pk[CRYPTO_PUBLICKEYBYTES];
    unsigned char sk[CRYPTO_SECRETKEYBYTES];
    unsigned char seed[CRYPTO_SEEDBYTES];

    for (size_t i = 0; i < sizeof(seed); i++) {
        seed[i] = (unsigned char)i;
    }

    if (crypto_sign_seed_keypair(pk, sk, seed) != 0) {
        fprintf(stderr, "crypto_sign_seed_keypair failed\n");
        return 1;
    }

    printf("keypair generated: pk=%llu sk=%llu seed=%llu\n",
           crypto_sign_publickeybytes(),
           crypto_sign_secretkeybytes(),
           crypto_sign_seedbytes());
    return 0;
}
