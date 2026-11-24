#include <stdio.h>
#include <string.h>

#include "drng.h"
#include "params.h"
#include "SIG_AlgorithmInstance.h"

DRNG_ctx drng_algorithm;

extern void fault_arm_threshold(size_t threshold);
extern unsigned long fault_count_get(void);

int main(void)
{
    unsigned char seed[64];
    unsigned char msg1[17];
    unsigned char msg2[5000];
    unsigned char pk[BIT_PUBLICKEYBYTES];
    unsigned char sk[BIT_SECRETKEYBYTES];
    unsigned char sig[BIT_SIGNBYTES];
    unsigned char sig_first[BIT_SIGNBYTES];
    unsigned long long pk_len = sig_get_pk_len_bytes();
    unsigned long long sk_len = sig_get_sk_len_bytes();
    unsigned long long sig_len = sig_get_sn_len_bytes();
    int first_rc, fault_rc, verify_previous, verify_requested;

    memset(seed, 0x42, sizeof(seed));
    memset(msg1, 0x11, sizeof(msg1));
    memset(msg2, 0x22, sizeof(msg2));
    if (init_random_number(&drng_algorithm, seed, sizeof(seed)) != 0)
        return 2;
    if (sig_keygen(pk, &pk_len, sk, &sk_len) != 0)
        return 3;

    first_rc = sig_sign(sk, sk_len, msg1, sizeof(msg1), sig, &sig_len);
    memcpy(sig_first, sig, sizeof(sig_first));
    if (first_rc != 0 || sig_verify(pk, pk_len, sig_first, sig_len,
                                   msg1, sizeof(msg1)) != 0)
        return 4;

    fault_arm_threshold(4096);
    fault_rc = sig_sign(sk, sk_len, msg2, sizeof(msg2), sig, &sig_len);
    verify_previous = sig_verify(pk, pk_len, sig, sig_len,
                                 msg1, sizeof(msg1));
    verify_requested = sig_verify(pk, pk_len, sig, sig_len,
                                  msg2, sizeof(msg2));

    printf("first_sign_rc=%d\n", first_rc);
    printf("faulted_sign_rc=%d\n", fault_rc);
    printf("fault_count=%lu\n", fault_count_get());
    printf("signature_len=%llu\n", sig_len);
    printf("verify_previous=%d\n", verify_previous);
    printf("verify_requested=%d\n", verify_requested);
    return 0;
}
