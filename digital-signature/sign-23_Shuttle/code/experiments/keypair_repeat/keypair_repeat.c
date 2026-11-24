#include <stdio.h>
#include <string.h>

#include "api.h"
#include "drng.h"

DRNG_ctx drng_algorithm;

int main(void)
{
    uint8_t pk1[CRYPTO_PUBLICKEYBYTES], sk1[CRYPTO_SECRETKEYBYTES];
    uint8_t pk2[CRYPTO_PUBLICKEYBYTES], sk2[CRYPTO_SECRETKEYBYTES];
    uint8_t sig[CRYPTO_BYTES];
    size_t siglen = 0;
    const uint8_t msg[] = "attacker-selected-message";
    uint8_t bad[sizeof msg];
    int r1 = crypto_sign_keypair(pk1, sk1);
    int r2 = crypto_sign_keypair(pk2, sk2);
    int rs = crypto_sign_signature(sig, &siglen, msg, sizeof msg, sk2);
    int rv = crypto_sign_verify(sig, siglen, msg, sizeof msg, pk1);

    memcpy(bad, msg, sizeof msg);
    bad[0] ^= 1;
    int rnb = crypto_sign_verify(sig, siglen, bad, sizeof bad, pk1);

    printf("r1=%d r2=%d pk_equal=%d sk_equal=%d sign_attacker_key=%d verify_honest_pk=%d negative_control=%d\n",
           r1, r2,
           memcmp(pk1, pk2, sizeof pk1) == 0,
           memcmp(sk1, sk2, sizeof sk1) == 0, rs, rv, rnb);
    printf("first_pk_sha_prefix=");
    for (size_t i = 0; i < 16; i++)
        printf("%02x", pk1[i]);
    printf("\n");
    return 0;
}
