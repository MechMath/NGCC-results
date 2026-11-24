#include <stdio.h>
#include <string.h>

#include "drng.h"
#include "params.h"
#include "sign.h"
#include "SIG_AlgorithmInstance.h"

DRNG_ctx drng_algorithm;

extern void fault_arm(size_t size);
extern unsigned long fault_count_get(void);
extern void fault_log_enable(int enabled);
extern size_t fault_observed_size(unsigned long index);
extern unsigned long fault_observed_count(void);

static int same_bytes(const unsigned char *a, const unsigned char *b, size_t n)
{
    return memcmp(a, b, n) == 0;
}

int main(void)
{
    unsigned char secret_seed[64];
    unsigned char alternate_secret_seed[64];
    unsigned long long pk_len = sig_get_pk_len_bytes();
    unsigned long long sk_len = sig_get_sk_len_bytes();
    unsigned long long sig_len = sig_get_sn_len_bytes();
    unsigned char pk_control[BIT_PUBLICKEYBYTES];
    unsigned char sk_control[BIT_SECRETKEYBYTES];
    unsigned char pk_fault[BIT_PUBLICKEYBYTES];
    unsigned char sk_fault[BIT_SECRETKEYBYTES];
    unsigned char pk_alt[BIT_PUBLICKEYBYTES];
    unsigned char sk_alt[BIT_SECRETKEYBYTES];
    unsigned char pk_alt2[BIT_PUBLICKEYBYTES];
    unsigned char sk_alt2[BIT_SECRETKEYBYTES];
    unsigned char sig_control[BIT_SIGNBYTES];
    unsigned char sig_fault[BIT_SIGNBYTES];
    unsigned char msg[17];
    DRNG_ctx drng_zero;
    DRNG_ctx drng_fault;
    DRNG_ctx drng_alt;
    int rc;

    for (size_t i = 0; i < sizeof(secret_seed); i++)
        secret_seed[i] = (unsigned char)(0xa5 ^ (17 * i));
    memcpy(alternate_secret_seed, secret_seed, sizeof(secret_seed));
    for (size_t i = SEEDLEN; i < sizeof(alternate_secret_seed); i++)
        alternate_secret_seed[i] ^= 0xff;
    for (size_t i = 0; i < sizeof(msg); i++)
        msg[i] = (unsigned char)(0x31 + i);

    fault_arm(1 + 4 + sizeof(secret_seed));
    fault_log_enable(1);
    rc = init_random_number(&drng_fault, secret_seed, sizeof(secret_seed));
    printf("faulted_init_rc=%d fault_count=%lu\n",
           rc, fault_count_get());
    printf("observed_malloc_sizes=");
    for (unsigned long i = 0; i < fault_observed_count(); i++)
        printf("%zu%s", fault_observed_size(i),
               i + 1 == fault_observed_count() ? "\n" : ",");
    fault_log_enable(0);
    if (rc != 0) {
        fprintf(stderr, "faulted init returned failure, candidate not observed\n");
        return 5;
    }

    fault_arm(1 + 4 + sizeof(alternate_secret_seed));
    rc = init_random_number(&drng_zero, alternate_secret_seed,
                            sizeof(alternate_secret_seed));
    printf("second_faulted_init_rc=%d fault_count=%lu\n",
           rc, fault_count_get());
    if (rc != 0) {
        fprintf(stderr, "second faulted init returned failure\n");
        return 10;
    }
    printf("faulted_seeds_differing_only_after_byte55_equal_drng=%d\n",
           same_bytes((const unsigned char *)&drng_fault,
                      (const unsigned char *)&drng_zero, sizeof(drng_zero)));

    drng_algorithm = drng_fault;
    rc = sig_keygen(pk_fault, &pk_len, sk_fault, &sk_len);
    if (rc != 0) {
        fprintf(stderr, "faulted keygen failed: %d\n", rc);
        return 6;
    }
    drng_algorithm = drng_zero;
    rc = sig_keygen(pk_control, &pk_len, sk_control, &sk_len);
    if (rc != 0) {
        fprintf(stderr, "second faulted keygen failed: %d\n", rc);
        return 11;
    }
    drng_algorithm = drng_fault;
    rc = sig_sign(sk_fault, sk_len, msg, sizeof(msg), sig_fault, &sig_len);
    if (rc != 0) {
        fprintf(stderr, "faulted sign failed: %d\n", rc);
        return 7;
    }
    drng_algorithm = drng_zero;
    rc = sig_sign(sk_control, sk_len, msg, sizeof(msg), sig_control, &sig_len);
    if (rc != 0) {
        fprintf(stderr, "second faulted sign failed: %d\n", rc);
        return 12;
    }

    rc = init_random_number(&drng_alt, secret_seed, sizeof(secret_seed));
    if (rc != 0) {
        fprintf(stderr, "unfaulted secret-seed init failed: %d\n", rc);
        return 8;
    }
    drng_algorithm = drng_alt;
    rc = sig_keygen(pk_alt, &pk_len, sk_alt, &sk_len);
    if (rc != 0) {
        fprintf(stderr, "unfaulted secret-seed keygen failed: %d\n", rc);
        return 9;
    }

    {
        DRNG_ctx drng_alt2;
        rc = init_random_number(&drng_alt2, alternate_secret_seed,
                                sizeof(alternate_secret_seed));
        if (rc != 0)
            return 13;
        drng_algorithm = drng_alt2;
        rc = sig_keygen(pk_alt2, &pk_len, sk_alt2, &sk_len);
        if (rc != 0)
            return 14;
    }

    printf("pk_from_two_different_faulted_seeds_equal=%d\n",
           same_bytes(pk_fault, pk_control, sizeof(pk_control)));
    printf("sk_from_two_different_faulted_seeds_equal=%d\n",
           same_bytes(sk_fault, sk_control, sizeof(sk_control)));
    printf("pk_unfaulted_secret_seed_differs=%d\n",
           !same_bytes(pk_alt, pk_fault, sizeof(pk_alt)));
    printf("unfaulted_suffix_variants_produce_different_pks=%d\n",
           !same_bytes(pk_alt, pk_alt2, sizeof(pk_alt)));
    printf("unfaulted_suffix_variants_produce_different_sks=%d\n",
           !same_bytes(sk_alt, sk_alt2, sizeof(sk_alt)));
    printf("faulted_sig_verifies_other_faulted_seed_pk=%d\n",
           sig_verify(pk_control, pk_len, sig_fault, sig_len, msg, sizeof(msg)));
    printf("sig_from_two_different_faulted_seeds_equal=%d\n",
           same_bytes(sig_fault, sig_control, sizeof(sig_control)));
    return 0;
}
