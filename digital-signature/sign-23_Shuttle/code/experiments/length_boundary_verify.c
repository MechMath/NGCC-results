#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "api.h"

int main(void)
{
    uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[CRYPTO_SECRETKEYBYTES];
    uint8_t sig[CRYPTO_BYTES];
    uint8_t m[8193] = {0};
    size_t siglen = 0;
    int kg = crypto_sign_keypair(pk, sk);
    int sg = crypto_sign_signature(sig, &siglen, m, 8192, sk);
    int v8192 = crypto_sign_verify(sig, siglen, m, 8192, pk);
    int sg8193 = crypto_sign_signature(sig, &siglen, m, 8193, sk);
    size_t sig8192len = CRYPTO_BYTES;
    sg = crypto_sign_signature(sig, &sig8192len, m, 8192, sk);
    int v8193 = crypto_sign_verify(sig, sig8192len, m, 8193, pk);

    printf("keygen=%d sign8192=%d verify8192=%d sign8193=%d verify8193=%d\n",
           kg, sg, v8192, sg8193, v8193);
    return 0;
}
