#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "api.h"
#include "drng.h"
#include "faest.h"

DRNG_ctx drng_algorithm;

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: %s valid|0|1|2757\n", argv[0]);
        return 2;
    }

    unsigned char pk[CRYPTO_PUBLICKEYBYTES] = {0};
    unsigned char sk[CRYPTO_SECRETKEYBYTES] = {0};
    const unsigned char message[16] = "asan-control-msg";
    unsigned char sm[sizeof(message) + CRYPTO_BYTES];
    unsigned char sm2[sizeof(message) + CRYPTO_BYTES];
    unsigned char opened[sizeof(message) + CRYPTO_BYTES];
    unsigned long long smlen = 0;
    unsigned long long mlen = 0;
    unsigned char seed[64] = {0};

    init_random_number(&drng_algorithm, seed, sizeof(seed));

    int ret = crypto_sign_keypair(pk, sk);
    printf("keypair ret=%d\n", ret);
    fflush(stdout);
    if (ret != 0)
        return 3;

    if (strcmp(argv[1], "valid") == 0) {
        ret = crypto_sign(sm, &smlen, message, sizeof(message), sk);
        printf("sign ret=%d smlen=%llu\n", ret, smlen);
        fflush(stdout);
        if (ret != 0)
            return 4;
        ret = crypto_sign_open(opened, &mlen, sm, smlen, pk);
        printf("open ret=%d mlen=%llu equal=%d\n", ret, mlen,
               mlen == sizeof(message) &&
               memcmp(opened, message, sizeof(message)) == 0);
        unsigned long long smlen2 = 0;
        int ret2 = crypto_sign(sm2, &smlen2, message, sizeof(message), sk);
        printf("second_sign ret=%d smlen=%llu signatures_equal=%d\n",
               ret2, smlen2,
               smlen == smlen2 && memcmp(sm, sm2, smlen) == 0);
        return ret == 0 && ret2 == 0 ? 0 : 5;
    }

    smlen = strtoull(argv[1], NULL, 10);
    memset(sm, 0xa5, sizeof(sm));
    printf("calling crypto_sign_open smlen=%llu FAEST_SIGNATURE_BYTES=%d\n",
           smlen, FAEST_SIGNATURE_BYTES);
    fflush(stdout);
    ret = crypto_sign_open(opened, &mlen, sm, smlen, pk);
    printf("open ret=%d mlen=%llu\n", ret, mlen);
    return 0;
}
