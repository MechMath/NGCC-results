#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "api.h"

static int exercise(size_t mlen)
{
    uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[CRYPTO_SECRETKEYBYTES];
    uint8_t sig[CRYPTO_BYTES];
    uint8_t *m = calloc(mlen ? mlen : 1, 1);
    size_t siglen = 0;
    int keygen_rc;
    int sign_rc;
    int verify_rc = -99;

    if (m == NULL)
        return 100;
    if (mlen)
        m[0] = 0x5a;
        m[mlen - 1] = 0xa5;

    keygen_rc = crypto_sign_keypair(pk, sk);
    if (keygen_rc == 0)
        sign_rc = crypto_sign_signature(sig, &siglen, m, mlen, sk);
    else
        sign_rc = -99;
    if (keygen_rc == 0 && sign_rc == 0)
        verify_rc = crypto_sign_verify(sig, siglen, m, mlen, pk);

    printf("mlen=%zu keygen=%d sign=%d siglen=%zu verify=%d\n",
           mlen, keygen_rc, sign_rc, siglen, verify_rc);
    free(m);
    return 0;
}

int main(void)
{
    int rc = 0;
    rc |= exercise(8192);
    rc |= exercise(8193);
    return rc;
}
