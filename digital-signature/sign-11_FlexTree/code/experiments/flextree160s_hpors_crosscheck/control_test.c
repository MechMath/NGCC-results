#include <stdio.h>
#include <string.h>

#include "api.h"
#include "drng.h"

DRNG_ctx drng_algorithm;

static int initialize(void)
{
    unsigned char seed[64];
    memset(seed, 0x42, sizeof(seed));
    return init_random_number(&drng_algorithm, seed, sizeof(seed) * 8);
}

int main(void)
{
    unsigned char pk[CRYPTO_PUBLICKEYBYTES];
    unsigned char sk[CRYPTO_SECRETKEYBYTES];
    unsigned char sig1[CRYPTO_BYTES];
    unsigned char sig2[CRYPTO_BYTES];
    const unsigned char msg[] = "FlexTree conformance control message";
    size_t siglen1 = 0, siglen2 = 0;
    int rc;

    if (initialize() != 0) {
        puts("DRNG_INIT_FAIL");
        return 2;
    }
    rc = crypto_sign_keypair(pk, sk);
    printf("KEYGEN_RC=%d PK_BYTES=%llu SK_BYTES=%llu SIGNATURE_BYTES=%llu\n",
           rc, crypto_sign_publickeybytes(), crypto_sign_secretkeybytes(),
           crypto_sign_bytes());
    if (rc != 0) return 3;

    rc = crypto_sign_signature(sig1, &siglen1, msg, sizeof(msg) - 1, sk);
    printf("SIGN1_RC=%d LEN=%zu VERIFY=%d\n", rc, siglen1,
           crypto_sign_verify(sig1, siglen1, msg, sizeof(msg) - 1, pk));
    rc = crypto_sign_signature(sig2, &siglen2, msg, sizeof(msg) - 1, sk);
    printf("SIGN2_RC=%d LEN=%zu VERIFY=%d EQUAL_SIG=%d\n", rc, siglen2,
           crypto_sign_verify(sig2, siglen2, msg, sizeof(msg) - 1, pk),
           siglen1 == siglen2 && memcmp(sig1, sig2, siglen1) == 0);

    {
        unsigned char altered_msg[sizeof(msg) - 1];
        memcpy(altered_msg, msg, sizeof(altered_msg));
        altered_msg[0] ^= 1;
        printf("ALTERED_MESSAGE_VERIFY=%d\n",
               crypto_sign_verify(sig1, siglen1, altered_msg,
                                  sizeof(altered_msg), pk));
    }
    {
        unsigned char altered_sig[CRYPTO_BYTES];
        memcpy(altered_sig, sig1, sizeof(altered_sig));
        altered_sig[CRYPTO_BYTES - 1] ^= 1;
        printf("ALTERED_SIGNATURE_VERIFY=%d\n",
               crypto_sign_verify(altered_sig, siglen1,
                                  msg, sizeof(msg) - 1, pk));
        printf("TRUNCATED_SIGNATURE_VERIFY=%d\n",
               crypto_sign_verify(sig1, siglen1 - 1,
                                  msg, sizeof(msg) - 1, pk));
    }
    {
        unsigned char pk2[CRYPTO_PUBLICKEYBYTES];
        unsigned char sk2[CRYPTO_SECRETKEYBYTES];
        rc = crypto_sign_keypair(pk2, sk2);
        printf("CROSS_KEY_VERIFY=%d KEYGEN2_RC=%d\n",
               crypto_sign_verify(sig1, siglen1, msg,
                                  sizeof(msg) - 1, pk2), rc);
    }
    return 0;
}
