#include "api.h"
#include <stdio.h>
#include <stdlib.h>

int main(void)
{
    unsigned char pk[CRYPTO_PUBLICKEYBYTES];
    unsigned char sk[CRYPTO_SECRETKEYBYTES];
    unsigned char sig[CRYPTO_BYTES];
    unsigned char one = 0;
    size_t siglen = 0;

    if (crypto_sign_keypair(pk, sk) != 0) return 2;
    if (crypto_sign_signature(sig, &siglen, &one, 0, sk) != 0) return 2;
    int nonnull = crypto_sign_verify(sig, siglen, &one, 0, pk);
    int null0 = crypto_sign_verify(sig, siglen, NULL, 0, pk);
    printf("empty_nonnull_signature=%d\n", nonnull);
    printf("empty_null_verify=%d\n", null0);
    return (nonnull == 0 && null0 == 0) ? 0 : 1;
}
