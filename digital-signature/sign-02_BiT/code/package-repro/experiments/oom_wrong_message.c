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

    fill(seed, sizeof(seed), 0x31);
    pk = calloc(1, pk_len);
    sk = calloc(1, sk_len);
    sig = calloc(1, sn_len);
    m1 = malloc(message_len);
    m2 = malloc(message_len);
    if (!pk || !sk || !sig || !m1 || !m2)
        return 2;
    fill(m1, message_len, 0x11);
    fill(m2, message_len, 0xa7);

    rc = init_random_number(&drng_algorithm, seed, sizeof(seed));
    if (rc != 0)
        return 3;
    rc = sig_keygen(pk, &pk_len, sk, &sk_len);
    if (rc != 0)
        return 4;

    /* Seed the reused signer stack slot with message_hash(pk, m1). */
    rc = sig_sign(sk, sk_len, m1, message_len, sig, &sn_len);
    if (rc != 0 || sn_len != sig_get_sn_len_bytes())
        return 5;

    /*
     * The next call asks for a signature on m2. Its concatenation buffer is
     * over 4096 bytes, so the submitted message-hash helper calls malloc.
     * Fail exactly that allocation. The helper returns without initializing
     * message_hash; sig_sign ignores that failure and continues.
     */
    memset(sig, 0, sig_get_sn_len_bytes());
    sn_len = sig_get_sn_len_bytes();
    malloc_fault_arm(4096);
    rc = sig_sign(sk, sk_len, m2, message_len, sig, &sn_len);

    out = fopen(argc > 1 ? argv[1] : "oom_wrong_message.txt", "w");
    if (!out)
        return 6;
    fprintf(out, "archive_sha256=698fbe834279a4100a66c20f3e0b634c738e1150936acf74b55efc6db6975e8d\n");
    fprintf(out, "algorithm=BiT-512\n");
    fprintf(out, "message_len=%zu\n", message_len);
    fprintf(out, "malloc_fault_minimum_size=4096\n");
    fprintf(out, "malloc_fault_count=%lu\n", malloc_fault_count());
    fprintf(out, "faulted_sign_rc=%d\n", rc);
    fprintf(out, "faulted_sign_len=%llu\n", sn_len);
    fprintf(out, "faulted_signature_returned_as_success=%d\n", rc == 0);
    if (rc == 0) {
        int verify_m1 = sig_verify(pk, pk_len, sig, sn_len, m1, message_len);
        int verify_m2 = sig_verify(pk, pk_len, sig, sn_len, m2, message_len);
        fprintf(out, "verify_against_previous_message=%d\n", verify_m1);
        fprintf(out, "verify_against_requested_message=%d\n", verify_m2);
        fprintf(out, "wrong_message_signature_is_valid=%d\n",
                verify_m1 == 0 && verify_m2 != 0);
    }

    /* Positive control: an untouched sign/verify on the requested message. */
    memset(sig, 0, sig_get_sn_len_bytes());
    sn_len = sig_get_sn_len_bytes();
    rc = sig_sign(sk, sk_len, m2, message_len, sig, &sn_len);
    fprintf(out, "control_sign_rc=%d\n", rc);
    fprintf(out, "control_sign_len=%llu\n", sn_len);
    if (rc == 0)
        fprintf(out, "control_verify_rc=%d\n",
                sig_verify(pk, pk_len, sig, sn_len, m2, message_len));

    fclose(out);
    return 0;
}
