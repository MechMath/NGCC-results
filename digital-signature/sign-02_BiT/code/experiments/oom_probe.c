#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "SIG_AlgorithmInstance.h"
#include "drng.h"

DRNG_ctx drng_algorithm;

extern DRNG_ctx drng_algorithm;

void bit_fault_arm(size_t min_size);
void bit_fault_disarm(void);
uint64_t bit_fault_count(void);
size_t bit_fault_size(void);

enum probe_mode {
    MODE_ARMED_AFTER_M1 = 1,
    MODE_UNARMED_AFTER_M1 = 2,
    MODE_ARMED_FRESH = 3,
};

static void fill(uint8_t *p, size_t n, uint8_t tag)
{
    for (size_t i = 0; i < n; i++)
        p[i] = (uint8_t)(tag + (i * 131u) + (i >> 3));
}

static void print_hex_prefix(const char *label, const uint8_t *p, size_t n)
{
    printf("%s=", label);
    for (size_t i = 0; i < n; i++)
        printf("%02x", p[i]);
    putchar('\n');
}

int main(int argc, char **argv)
{
    const int mode = argc > 1 ? atoi(argv[1]) : MODE_ARMED_AFTER_M1;
    const size_t msg_len = 5000;
    uint8_t seed[64];
    uint8_t *m1 = malloc(msg_len);
    uint8_t *m2 = malloc(msg_len);
    uint8_t *pk = malloc(sig_get_pk_len_bytes());
    uint8_t *sk = malloc(sig_get_sk_len_bytes());
    uint8_t *sig1 = malloc(sig_get_sn_len_bytes());
    uint8_t *sig2 = malloc(sig_get_sn_len_bytes());
    uint8_t *sig3 = malloc(sig_get_sn_len_bytes());
    unsigned long long pk_len = sig_get_pk_len_bytes();
    unsigned long long sk_len = sig_get_sk_len_bytes();
    unsigned long long sn1_len = sig_get_sn_len_bytes();
    unsigned long long sn2_len = sig_get_sn_len_bytes();
    unsigned long long sn3_len = sig_get_sn_len_bytes();
    int rc;

    if (!m1 || !m2 || !pk || !sk || !sig1 || !sig2 || !sig3)
        return 100;
    fill(seed, sizeof(seed), 0x19);
    fill(m1, msg_len, 0x31);
    fill(m2, msg_len, 0xa7);
    memset(pk, 0, sig_get_pk_len_bytes());
    memset(sk, 0, sig_get_sk_len_bytes());
    memset(sig1, 0, sig_get_sn_len_bytes());
    memset(sig2, 0x5a, sig_get_sn_len_bytes());
    memset(sig3, 0, sig_get_sn_len_bytes());

    rc = init_random_number(&drng_algorithm, seed, sizeof(seed));
    printf("init_rc=%d\n", rc);
    if (rc)
        return 101;
    rc = sig_keygen(pk, &pk_len, sk, &sk_len);
    printf("keygen_rc=%d pk_len=%llu sk_len=%llu\n", rc, pk_len, sk_len);
    if (rc)
        return 102;

    if (mode != MODE_ARMED_FRESH) {
        rc = sig_sign(sk, sk_len, m1, msg_len, sig1, &sn1_len);
        /*
         * Do not place a verifier call between the two signing calls: its
         * stack frame would overwrite the signer's retained local slot.
         * The accepted claim specifies consecutive signing calls.
         */
        printf("first_sign_rc=%d first_len=%llu\n", rc, sn1_len);
        if (rc)
            return 103;
    }

    if (mode == MODE_ARMED_AFTER_M1 || mode == MODE_ARMED_FRESH) {
        bit_fault_arm(4096);
    }
    rc = sig_sign(sk, sk_len, m2, msg_len, sig2, &sn2_len);
    bit_fault_disarm();
    printf("second_sign_rc=%d second_len=%llu fault_count=%llu fault_size=%zu\n",
           rc, sn2_len, (unsigned long long)bit_fault_count(), bit_fault_size());
    printf("second_verify_m1=%d second_verify_m2=%d\n",
           sig_verify(pk, pk_len, sig2, sn2_len, m1, msg_len),
           sig_verify(pk, pk_len, sig2, sn2_len, m2, msg_len));
    printf("second_equals_first=%d\n",
           !memcmp(sig1, sig2, sig_get_sn_len_bytes()));
    print_hex_prefix("second_prefix16", sig2, 16);

    rc = sig_sign(sk, sk_len, m2, msg_len, sig3, &sn3_len);
    printf("control_sign_rc=%d control_len=%llu control_verify_m1=%d control_verify_m2=%d\n",
           rc, sn3_len,
           sig_verify(pk, pk_len, sig3, sn3_len, m1, msg_len),
           sig_verify(pk, pk_len, sig3, sn3_len, m2, msg_len));
    printf("control_equals_first=%d\n",
           !memcmp(sig1, sig3, sig_get_sn_len_bytes()));

    if (mode == MODE_ARMED_AFTER_M1 && rc == 0 && sn2_len == sig_get_sn_len_bytes() &&
        sig_verify(pk, pk_len, sig2, sn2_len, m1, msg_len) == 0 &&
        sig_verify(pk, pk_len, sig2, sn2_len, m2, msg_len) != 0 &&
        sig_verify(pk, pk_len, sig3, sn3_len, m2, msg_len) == 0)
        return 0;
    if (mode == MODE_UNARMED_AFTER_M1 && rc == 0 &&
        sig_verify(pk, pk_len, sig2, sn2_len, m1, msg_len) != 0 &&
        sig_verify(pk, pk_len, sig2, sn2_len, m2, msg_len) == 0)
        return 0;
    if (mode == MODE_ARMED_FRESH)
        return 0;
    return 1;
}
