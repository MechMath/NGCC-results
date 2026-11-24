#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "SIG_AlgorithmInstance.h"
#include "drng.h"

void arm_malloc_fault(void);
unsigned long malloc_fault_count(void);
DRNG_ctx drng_algorithm;

static int run_case(const char *name)
{
    unsigned long long pk_len = sig_get_pk_len_bytes();
    unsigned long long sk_len = sig_get_sk_len_bytes();
    unsigned long long sn_len = sig_get_sn_len_bytes();
    unsigned char *pk = calloc(1, (size_t)pk_len);
    unsigned char *sk = calloc(1, (size_t)sk_len);
    unsigned char *sn = calloc(1, (size_t)sn_len);
    unsigned char *m1 = (unsigned char *)"previous-message-0123456789";
    unsigned char *m2 = malloc(5000);
    unsigned long long out_len = 0;
    unsigned char drng_seed[SEEDLEN];
    int rc;

    if (pk == NULL || sk == NULL || sn == NULL || m2 == NULL) {
        fprintf(stderr, "%s: setup allocation failed\n", name);
        return 2;
    }
    memset(m2, 'B', 5000);
    for (size_t i = 0; i < sizeof(drng_seed); ++i) {
        drng_seed[i] = (unsigned char)i;
    }
    if (init_random_number(&drng_algorithm, drng_seed, sizeof(drng_seed)) != 0) {
        fprintf(stderr, "%s: DRNG initialization failed\n", name);
        return 3;
    }

    rc = sig_keygen(pk, &pk_len, sk, &sk_len);
    if (rc != 0) {
        fprintf(stderr, "%s: keygen rc=%d\n", name, rc);
        return 3;
    }

    out_len = sn_len;
    rc = sig_sign(sk, sk_len, m1, strlen((char *)m1), sn, &out_len);
    if (rc != 0) {
        fprintf(stderr, "%s: initial sign rc=%d\n", name, rc);
        return 4;
    }

    memset(sn, 0, (size_t)sn_len);
    out_len = 0;
    arm_malloc_fault();
    rc = sig_sign(sk, sk_len, m2, 5000, sn, &out_len);
    printf("%s malloc_fault_count=%lu faulted_sign_rc=%d faulted_sign_len=%llu\n",
           name, malloc_fault_count(), rc, out_len);
    printf("%s verify_against_previous_message=%d verify_against_requested_message=%d\n",
           name,
           sig_verify(pk, pk_len, sn, out_len, m1,
                      (unsigned long long)strlen((char *)m1)),
           sig_verify(pk, pk_len, sn, out_len, m2, 5000));

    out_len = sn_len;
    rc = sig_sign(sk, sk_len, m2, 5000, sn, &out_len);
    printf("%s control_sign_rc=%d control_sign_len=%llu control_verify_requested=%d\n",
           name, rc, out_len,
           sig_verify(pk, pk_len, sn, out_len, m2, 5000));

    free(m2);
    free(sn);
    free(sk);
    free(pk);
    return 0;
}

int main(int argc, char **argv)
{
    return run_case(argc > 1 ? argv[1] : "implementation");
}
