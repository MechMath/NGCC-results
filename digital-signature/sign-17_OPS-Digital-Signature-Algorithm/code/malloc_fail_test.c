#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "SIG_AlgorithmInstance.h"
#include "drng.h"
#include "params.h"

DRNG_ctx drng_algorithm;

static int fail_next_malloc;

void *__real_malloc(size_t size);

void *__wrap_malloc(size_t size)
{
    if (fail_next_malloc) {
        fail_next_malloc = 0;
        return NULL;
    }
    return __real_malloc(size);
}

int main(void)
{
    uint8_t seed[55] = {0};
    uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[CRYPTO_SECRETKEYBYTES];
    uint8_t message[1] = {0x42};
    uint8_t signature[CRYPTO_BYTES];
    unsigned long long pk_len = 0;
    unsigned long long sk_len = 0;
    unsigned long long sig_len = 0;

    if (init_random_number(&drng_algorithm, seed, sizeof(seed)) != 0)
        return 10;
    if (sig_keygen(pk, &pk_len, sk, &sk_len) != 0)
        return 11;

    fail_next_malloc = 1;
    int failed_rc = sig_sign(sk, sk_len, message, sizeof(message),
                             signature, &sig_len);
    printf("forced_failure rc=%d sig_len=%llu\n", failed_rc, sig_len);

    sig_len = 0;
    int control_rc = sig_sign(sk, sk_len, message, sizeof(message),
                              signature, &sig_len);
    int verify_rc = sig_verify(pk, pk_len, signature, sig_len,
                               message, sizeof(message));
    printf("control rc=%d sig_len=%llu verify=%d expected_sig_len=%d\n",
           control_rc, sig_len, verify_rc, CRYPTO_BYTES);

    return 0;
}
