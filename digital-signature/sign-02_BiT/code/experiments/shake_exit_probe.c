#include <stdio.h>
#include <string.h>

#include "drng.h"
#include "params.h"
#include "SIG_AlgorithmInstance.h"

DRNG_ctx drng_algorithm;

extern void fault_arm(size_t size);
extern unsigned long fault_count_get(void);

int main(int argc, char **argv)
{
    unsigned char seed[64];
    unsigned char msg[17];
    unsigned char pk[BIT_PUBLICKEYBYTES];
    unsigned char sk[BIT_SECRETKEYBYTES];
    unsigned char sig[BIT_SIGNBYTES];
    unsigned long long pk_len = sig_get_pk_len_bytes();
    unsigned long long sk_len = sig_get_sk_len_bytes();
    unsigned long long sig_len = sig_get_sn_len_bytes();
    int rc;

    memset(seed, 0x42, sizeof(seed));
    memset(msg, 0x17, sizeof(msg));
    rc = init_random_number(&drng_algorithm, seed, sizeof(seed));
    if (rc != 0)
        return 2;
    rc = sig_keygen(pk, &pk_len, sk, &sk_len);
    if (rc != 0)
        return 3;

    if (argc > 1 && strcmp(argv[1], "fault") == 0) {
        fault_arm(26 * sizeof(unsigned long long));
        printf("armed_public_sig_sign\n");
        fflush(stdout);
    }

    rc = sig_sign(sk, sk_len, msg, sizeof(msg), sig, &sig_len);
    printf("sig_sign_returned=%d fault_count=%lu\n", rc, fault_count_get());
    return rc == 0 ? 0 : 4;
}
