#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "SIG_AlgorithmInstance.h"
#include "drng.h"

DRNG_ctx drng_algorithm;

void malloc_fault_arm(size_t size);
unsigned long malloc_fault_count(void);
size_t malloc_fault_last_size(void);

static void
fill(uint8_t *p, size_t n, uint8_t tag)
{
    size_t i;

    for (i = 0; i < n; i++)
        p[i] = (uint8_t)(tag + (uint8_t)(i * 131u));
}

static int
bytes_equal(const uint8_t *a, const uint8_t *b, size_t n)
{
    return memcmp(a, b, n) == 0;
}

int
main(int argc, char **argv)
{
    const size_t message_len = 5000;
    const int no_prior = argc > 2 && strcmp(argv[2], "no-prior") == 0;
    uint8_t seed[64];
    uint8_t *pk;
    uint8_t *sk;
    uint8_t *first;
    uint8_t *faulted;
    uint8_t *control;
    uint8_t *m1;
    uint8_t *m2;
    unsigned long long pk_len = sig_get_pk_len_bytes();
    unsigned long long sk_len = sig_get_sk_len_bytes();
    const unsigned long long sig_len = sig_get_sn_len_bytes();
    unsigned long long len;
    unsigned long long faulted_len = 0;
    FILE *out;
    int first_rc = -999;
    int faulted_rc;
    int control_rc;
    int verify_m1 = -999;
    int verify_m2 = -999;
    int control_verify_m1 = -999;
    int control_verify_m2 = -999;

    fill(seed, sizeof(seed), 0x31);
    pk = calloc(1, pk_len);
    sk = calloc(1, sk_len);
    first = calloc(1, sig_len);
    faulted = calloc(1, sig_len);
    control = calloc(1, sig_len);
    m1 = malloc(message_len);
    m2 = malloc(message_len);
    if (!pk || !sk || !first || !faulted || !control || !m1 || !m2)
        return 2;
    fill(m1, message_len, 0x11);
    fill(m2, message_len, 0xa7);

    if (init_random_number(&drng_algorithm, seed, sizeof(seed)) != 0)
        return 3;
    if (sig_keygen(pk, &pk_len, sk, &sk_len) != 0)
        return 4;

    if (!no_prior) {
        len = sig_len;
        first_rc = sig_sign(sk, sk_len, m1, message_len, first, &len);
        if (first_rc != 0 || len != sig_len)
            return 5;
    }

    len = sig_len;
    malloc_fault_arm(4096);
    faulted_rc = sig_sign(sk, sk_len, m2, message_len, faulted, &len);
    faulted_len = len;
    if (faulted_rc == 0) {
        verify_m1 = sig_verify(pk, pk_len, faulted, faulted_len, m1,
                               message_len);
        verify_m2 = sig_verify(pk, pk_len, faulted, faulted_len, m2,
                               message_len);
    }

    len = sig_len;
    control_rc = sig_sign(sk, sk_len, m2, message_len, control, &len);
    if (control_rc == 0) {
        control_verify_m1 =
            sig_verify(pk, pk_len, control, len, m1, message_len);
        control_verify_m2 =
            sig_verify(pk, pk_len, control, len, m2, message_len);
    }

    out = fopen(argc > 1 ? argv[1] : "oom_audit_matrix.txt", "w");
    if (!out)
        return 6;
    fprintf(out, "archive_sha256=698fbe834279a4100a66c20f3e0b634c738e1150936acf74b55efc6db6975e8d\n");
    fprintf(out, "algorithm=BiT-512\n");
    fprintf(out, "mode=%s\n", no_prior ? "no-prior" : "prior-m1");
    fprintf(out, "message_len=%zu\n", message_len);
    fprintf(out, "malloc_fault_minimum_size=4096\n");
    fprintf(out, "malloc_fault_count=%lu\n", malloc_fault_count());
    fprintf(out, "fault_size=%zu\n", malloc_fault_last_size());
    if (!no_prior)
        fprintf(out, "first_sign_rc=%d\n", first_rc);
    fprintf(out, "faulted_sign_rc=%d\n", faulted_rc);
    fprintf(out, "faulted_sign_len=%llu\n", faulted_len);
    fprintf(out, "second_equals_first=%d\n",
            no_prior ? -1 : bytes_equal(first, faulted, (size_t)sig_len));
    fprintf(out, "faulted_verify_m1=%d\n", verify_m1);
    fprintf(out, "faulted_verify_m2=%d\n", verify_m2);
    fprintf(out, "control_sign_rc=%d\n", control_rc);
    fprintf(out, "control_verify_m1=%d\n", control_verify_m1);
    fprintf(out, "control_verify_m2=%d\n", control_verify_m2);
    fclose(out);
    return 0;
}
