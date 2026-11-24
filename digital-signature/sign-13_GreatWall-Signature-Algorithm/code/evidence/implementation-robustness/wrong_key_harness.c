#include <stdio.h>
#include <string.h>

#include "SIG_AlgorithmInstance.h"
#include "api.h"
#include "drng.h"

DRNG_ctx drng_algorithm;

int main(void)
{
    unsigned char seed[64] = {0};
    unsigned char pk[CRYPTO_PUBLICKEYBYTES] = {0};
    unsigned char sk[CRYPTO_SECRETKEYBYTES] = {0};
    unsigned char bad_sk[CRYPTO_SECRETKEYBYTES] = {0};
    unsigned char message[15] = "wrong-key-ctrl";
    unsigned char good_sn[CRYPTO_BYTES] = {0};
    unsigned char bad_sn[CRYPTO_BYTES] = {0};
    unsigned long long pk_len = 0;
    unsigned long long sk_len = 0;
    unsigned long long good_sn_len = 0;
    unsigned long long bad_sn_len = 0;

    init_random_number(&drng_algorithm, seed, sizeof(seed));

    int ret = sig_keygen(pk, &pk_len, sk, &sk_len);
    printf("keygen ret=%d pk_len=%llu sk_len=%llu\n", ret, pk_len, sk_len);
    fflush(stdout);
    if (ret != 0)
        return 2;

    ret = sig_sign(sk, sk_len, message, sizeof(message),
                   good_sn, &good_sn_len);
    printf("honest_sign ret=%d sn_len=%llu\n", ret, good_sn_len);
    fflush(stdout);
    if (ret != 0)
        return 3;

    ret = sig_verify(pk, pk_len, good_sn, good_sn_len,
                     message, sizeof(message));
    printf("honest_verify ret=%d\n", ret);
    fflush(stdout);
    if (ret != 0)
        return 4;

    memset(bad_sn, 0xa5, sizeof(bad_sn));
    ret = sig_sign(bad_sk, sizeof(bad_sk), message, sizeof(message),
                   bad_sn, &bad_sn_len);
    printf("zero_key_sign_ret=%d sn_len=%llu first_byte=0x%02x\n",
           ret, bad_sn_len, bad_sn[0]);
    fflush(stdout);

    int verify_ret = sig_verify(pk, pk_len, bad_sn, bad_sn_len,
                                message, sizeof(message));
    printf("zero_key_signature_verify_ret=%d\n", verify_ret);
    fflush(stdout);
    return 0;
}
