#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "api.h"

static void print_hex(const char *label, const unsigned char *p, size_t n)
{
    printf("%s=", label);
    for (size_t i = 0; i < n; i++) {
        printf("%02x", p[i]);
    }
    putchar('\n');
}

int main(void)
{
    unsigned char pk[CRYPTO_PUBLICKEYBYTES];
    unsigned char sk[CRYPTO_SECRETKEYBYTES];
    unsigned char seed[CRYPTO_SEEDBYTES];

    for (size_t i = 0; i < sizeof(seed); i++) {
        seed[i] = (unsigned char)(0x5aU ^ i);
    }
    if (crypto_sign_seed_keypair(pk, sk, seed) != 0) {
        return 1;
    }
    print_hex("pk", pk, sizeof(pk));
    print_hex("sk", sk, sizeof(sk));
    return 0;
}
