#include "api.h"
#include "SIG_AlgorithmInstance.h"
#include "drng.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Signature verification does not use the DRNG. Define the adapter's global
 * only so this standalone verifier harness can link SIG_AlgorithmInstance.c. */
DRNG_ctx drng_algorithm;

int main(void)
{
    unsigned char pk[CRYPTO_PUBLICKEYBYTES];
    unsigned char sk[CRYPTO_SECRETKEYBYTES];
    unsigned char sig[CRYPTO_BYTES];
    unsigned char sig_zero_sklen[CRYPTO_BYTES];
    unsigned char msg[] = "QingLuan boundary controls";
    size_t siglen = 0;
    unsigned long long siglen_zero_sklen = 0;

    if (crypto_sign_keypair(pk, sk) != 0) {
        fprintf(stderr, "keypair failed\n");
        return 2;
    }
    if (crypto_sign_signature(sig, &siglen, msg, sizeof(msg) - 1, sk) != 0) {
        fprintf(stderr, "sign failed\n");
        return 2;
    }

    int honest = sig_verify(pk, CRYPTO_PUBLICKEYBYTES, sig, siglen,
                            msg, sizeof(msg) - 1);
    int zero_len = sig_verify(pk, 0, sig, siglen,
                              msg, sizeof(msg) - 1);
    int one_len = sig_verify(pk, 1, sig, siglen,
                             msg, sizeof(msg) - 1);
    int wrong_pklen = sig_verify(pk, CRYPTO_PUBLICKEYBYTES - 1, sig, siglen,
                                 msg, sizeof(msg) - 1);
    int sign_zero_sklen = sig_sign(sk, 0, msg, sizeof(msg) - 1,
                                   sig_zero_sklen, &siglen_zero_sklen);
    int verify_zero_sklen_sig = sig_verify(pk, CRYPTO_PUBLICKEYBYTES,
                                           sig_zero_sklen,
                                           siglen_zero_sklen,
                                           msg, sizeof(msg) - 1);

    printf("honest_pk_len=%d\n", honest);
    printf("zero_declared_pk_len=%d\n", zero_len);
    printf("one_declared_pk_len=%d\n", one_len);
    printf("short_declared_pk_len=%d\n", wrong_pklen);
    printf("sign_zero_sk_len=%d\n", sign_zero_sklen);
    printf("verify_signature_from_zero_sk_len=%d\n", verify_zero_sklen_sig);
    return (honest == 0 && zero_len == 0 && one_len == 0 && wrong_pklen == 0 &&
            sign_zero_sklen == 0 && verify_zero_sklen_sig == 0)
               ? 0 : 1;
}
