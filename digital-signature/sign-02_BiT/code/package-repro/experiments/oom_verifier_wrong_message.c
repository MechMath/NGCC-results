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

static void fill(uint8_t *p, size_t n, uint8_t tag)
{
    for (size_t i = 0; i < n; i++)
        p[i] = (uint8_t)(tag + (uint8_t)(i * 131u));
}

int main(int argc, char **argv)
{
    const size_t message_len = 5000;
    uint8_t seed[64];
    uint8_t *pk = NULL;
    uint8_t *sk = NULL;
    uint8_t *sig = NULL;
    uint8_t *m1 = NULL;
    uint8_t *m2 = NULL;
    unsigned long long pk_len = sig_get_pk_len_bytes();
    unsigned long long sk_len = sig_get_sk_len_bytes();
    unsigned long long sn_len = sig_get_sn_len_bytes();
    FILE *out;
    int rc;
    int seed_verify_rc;
    int faulted_verify_rc;
    int control_m1_rc;
    int control_m2_rc;

    fill(seed, sizeof(seed), 0x73);
    pk = calloc(1, pk_len);
    sk = calloc(1, sk_len);
    sig = calloc(1, sn_len);
    m1 = malloc(message_len);
    m2 = malloc(message_len);
    if (!pk || !sk || !sig || !m1 || !m2)
        return 2;
    fill(m1, message_len, 0x19);
    fill(m2, message_len, 0xb3);

    rc = init_random_number(&drng_algorithm, seed, sizeof(seed));
    if (rc != 0)
        return 3;
    rc = sig_keygen(pk, &pk_len, sk, &sk_len);
    if (rc != 0)
        return 4;
    rc = sig_sign(sk, sk_len, m1, message_len, sig, &sn_len);
    if (rc != 0 || sn_len != sig_get_sn_len_bytes())
        return 5;

    /* Seed the verifier's reused stack slot with D(pk,m1). */
    seed_verify_rc = sig_verify(pk, pk_len, sig, sn_len, m1, message_len);

    /*
     * The verifier asks for D(pk,m2). Fail exactly the hash buffer allocation;
     * bit_h512_2 returns without writing message_hash, and bit_sig_verify
     * ignores that failure.
     */
    malloc_fault_arm(4096);
    faulted_verify_rc = sig_verify(pk, pk_len, sig, sn_len, m2, message_len);

    /* Positive and negative controls without an armed allocation failure. */
    control_m1_rc = sig_verify(pk, pk_len, sig, sn_len, m1, message_len);
    control_m2_rc = sig_verify(pk, pk_len, sig, sn_len, m2, message_len);

    out = fopen(argc > 1 ? argv[1] : "oom_verifier_wrong_message.txt", "w");
    if (!out)
        return 6;
    fprintf(out, "archive_sha256=698fbe834279a4100a66c20f3e0b634c738e1150936acf74b55efc6db6975e8d\n");
    fprintf(out, "algorithm=BiT-512\n");
    fprintf(out, "message_len=%zu\n", message_len);
    fprintf(out, "malloc_fault_minimum_size=4096\n");
    fprintf(out, "malloc_fault_count=%lu\n", malloc_fault_count());
    fprintf(out, "seed_verify_against_signed_message=%d\n", seed_verify_rc);
    fprintf(out, "faulted_verify_against_previous_message=%d\n", faulted_verify_rc);
    fprintf(out, "faulted_verify_against_requested_other_message=%d\n", faulted_verify_rc);
    fprintf(out, "control_verify_against_signed_message=%d\n", control_m1_rc);
    fprintf(out, "control_verify_against_other_message=%d\n", control_m2_rc);
    fprintf(out, "wrong_message_verifier_acceptance=%d\n",
            faulted_verify_rc == 0 && control_m1_rc == 0 &&
            control_m2_rc != 0);
    fclose(out);
    return 0;
}
