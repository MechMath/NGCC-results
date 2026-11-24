#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "SIG_AlgorithmInstance.h"
#include "drng.h"
#include "api.h"

DRNG_ctx drng_algorithm;

static int check_pair(const uint8_t *sk, const uint8_t *pk,
                      const uint8_t *m1, size_t n1,
                      const uint8_t *m2, size_t n2,
                      const char *label) {
    uint8_t *sig1 = calloc(sig_get_sn_len_bytes(), 1);
    uint8_t *sig2 = calloc(sig_get_sn_len_bytes(), 1);
    unsigned long long l1 = 0, l2 = 0;
    if (!sig1 || !sig2) return 2;

    int s1 = sig_sign((unsigned char *)sk, sig_get_sk_len_bytes(),
                      (unsigned char *)m1, n1, sig1, &l1);
    int s2 = sig_sign((unsigned char *)sk, sig_get_sk_len_bytes(),
                      (unsigned char *)m2, n2, sig2, &l2);
    int same_signature = (l1 == l2 && memcmp(sig1, sig2, l1) == 0);
    int own1 = sig_verify((unsigned char *)pk, sig_get_pk_len_bytes(),
                          sig1, l1, (unsigned char *)m1, n1);
    int own2 = sig_verify((unsigned char *)pk, sig_get_pk_len_bytes(),
                          sig2, l2, (unsigned char *)m2, n2);
    int cross1 = sig_verify((unsigned char *)pk, sig_get_pk_len_bytes(),
                            sig1, l1, (unsigned char *)m2, n2);
    int cross2 = sig_verify((unsigned char *)pk, sig_get_pk_len_bytes(),
                            sig2, l2, (unsigned char *)m1, n1);

    printf("%s m1=%zu m2=%zu sign1=%d sign2=%d len1=%llu len2=%llu "
           "same_sig=%d own1=%d own2=%d cross1=%d cross2=%d\n",
           label, n1, n2, s1, s2, l1, l2,
           same_signature, own1, own2, cross1, cross2);
    free(sig1);
    free(sig2);
    return (s1 == 0 && s2 == 0 && own1 == 0 && own2 == 0) ? 0 : 1;
}

int main(void) {
    unsigned long long pkl = sig_get_pk_len_bytes();
    unsigned long long skl = sig_get_sk_len_bytes();
    uint8_t *pk = calloc(pkl, 1), *sk = calloc(skl, 1);
    if (!pk || !sk) return 2;
    if (sig_keygen(pk, &pkl, sk, &skl) != 0)
        return 3;

    printf("pk_len=%llu sk_len=%llu max_sig=%llu input_cap=8192 threshold=%llu\n",
           pkl, skl, sig_get_sn_len_bytes(), 8192 - pkl);

    size_t cap = 8192 - (size_t)pkl;
    uint8_t *m1 = calloc(cap + 2, 1);
    uint8_t *m2 = calloc(cap + 2, 1);
    if (!m1 || !m2) return 4;
    for (size_t i = 0; i < cap + 2; i++) {
        m1[i] = (uint8_t)(i * 17u + 3u);
        m2[i] = (uint8_t)(i * 29u + 11u);
    }

    int rc1 = check_pair(sk, pk, m1, cap, m2, cap,
                         "at_capacity_control");
    int rc2 = check_pair(sk, pk, m1, cap + 1, m2, cap + 1,
                         "one_byte_over");
    int rc3 = check_pair(sk, pk, m1, cap + 2, m2, cap + 2,
                         "two_bytes_over");
    free(m1);
    free(m2);
    free(pk);
    free(sk);
    return rc1 || rc2 || rc3 ? 10 : 0;
}
