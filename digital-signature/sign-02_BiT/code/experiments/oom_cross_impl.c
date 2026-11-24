#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "drng.h"
#include "SIG_AlgorithmInstance.h"

DRNG_ctx drng_algorithm;

extern void fault_arm_once_ge(size_t threshold);
extern void fault_disarm(void);
extern unsigned long long fault_count(void);
extern unsigned long long fault_seen_size(void);

static void fill(uint8_t *p, size_t n, uint8_t tag)
{
    for (size_t i = 0; i < n; i++)
        p[i] = (uint8_t)(tag + 37u * (uint8_t)i + (uint8_t)(i >> 8));
}

int main(void)
{
    uint8_t seed[64];
    for (size_t i = 0; i < sizeof(seed); i++)
        seed[i] = (uint8_t)(0xA5u ^ (uint8_t)(17u * i));

    if (init_random_number(&drng_algorithm, seed, sizeof(seed)) != 0) {
        fprintf(stderr, "drng init failed\n");
        return 2;
    }

    const unsigned long long pk_cap = sig_get_pk_len_bytes();
    const unsigned long long sk_cap = sig_get_sk_len_bytes();
    const unsigned long long sn_cap = sig_get_sn_len_bytes();
    uint8_t *pk = malloc((size_t)pk_cap);
    uint8_t *sk = malloc((size_t)sk_cap);
    uint8_t *sn1 = malloc((size_t)sn_cap);
    uint8_t *sn_fault = malloc((size_t)sn_cap);
    uint8_t *sn_control = malloc((size_t)sn_cap);
    uint8_t *m1 = malloc(5000);
    uint8_t *m2 = malloc(5000);
    if (!pk || !sk || !sn1 || !sn_fault || !sn_control || !m1 || !m2)
        return 3;
    fill(m1, 5000, 0x11);
    fill(m2, 5000, 0xE2);

    unsigned long long pk_len = pk_cap, sk_len = sk_cap, sn_len = sn_cap;
    int kg = sig_keygen(pk, &pk_len, sk, &sk_len);
    int s1 = sig_sign(sk, sk_len, m1, 5000, sn1, &sn_len);
    unsigned long long sn1_len = sn_len;

    fault_arm_once_ge(4096);
    sn_len = sn_cap;
    int sf = sig_sign(sk, sk_len, m2, 5000, sn_fault, &sn_len);
    unsigned long long snf_len = sn_len;
    fault_disarm();

    sn_len = sn_cap;
    int sc = sig_sign(sk, sk_len, m2, 5000, sn_control, &sn_len);
    unsigned long long snc_len = sn_len;

    int v1_m1 = sig_verify(pk, pk_len, sn1, sn1_len, m1, 5000);
    int v1_m2 = sig_verify(pk, pk_len, sn1, sn1_len, m2, 5000);
    int vf_m1 = sig_verify(pk, pk_len, sn_fault, snf_len, m1, 5000);
    int vf_m2 = sig_verify(pk, pk_len, sn_fault, snf_len, m2, 5000);
    int vc_m1 = sig_verify(pk, pk_len, sn_control, snc_len, m1, 5000);
    int vc_m2 = sig_verify(pk, pk_len, sn_control, snc_len, m2, 5000);

    int stale_matches_first = snf_len == sn1_len &&
        memcmp(sn_fault, sn1, (size_t)snf_len) == 0;
    printf("pk_len=%llu sk_len=%llu sn_cap=%llu\n", pk_len, sk_len, sn_cap);
    printf("keygen=%d first_sign=%d first_len=%llu\n", kg, s1, sn1_len);
    printf("fault_count=%llu fault_size=%llu faulted_sign=%d faulted_len=%llu\n",
           fault_count(), fault_seen_size(), sf, snf_len);
    printf("control_sign=%d control_len=%llu\n", sc, snc_len);
    printf("first_verify_m1=%d first_verify_m2=%d\n", v1_m1, v1_m2);
    printf("faulted_verify_m1=%d faulted_verify_m2=%d\n", vf_m1, vf_m2);
    printf("control_verify_m1=%d control_verify_m2=%d\n", vc_m1, vc_m2);
    printf("faulted_signature_equals_first=%d\n", stale_matches_first);

    int bug = kg == 0 && s1 == 0 && sf == 0 && sc == 0 &&
              v1_m1 == 0 && v1_m2 != 0 && vf_m1 == 0 && vf_m2 != 0 &&
              vc_m1 != 0 && vc_m2 == 0 && fault_count() == 1;
    printf("wrong_message_success_reproduced=%d\n", bug);

    free(m2);
    free(m1);
    free(sn_control);
    free(sn_fault);
    free(sn1);
    free(sk);
    free(pk);
    return bug ? 0 : 1;
}
