#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "SIG_AlgorithmInstance.h"
#include "drng.h"

DRNG_ctx drng_algorithm;

static void init_probe_drng(void)
{
    unsigned char seed[64];
    for (size_t i = 0; i < sizeof seed; i++) {
        seed[i] = (unsigned char)(0xA5u ^ (unsigned char)i);
    }
    if (init_random_number(&drng_algorithm, seed, sizeof seed) != 0) {
        fprintf(stderr, "probe: DRNG initialization failed\n");
        exit(2);
    }
}

int main(void)
{
    const unsigned long long pk_len = sig_get_pk_len_bytes();
    const unsigned long long sk_len = sig_get_sk_len_bytes();
    const unsigned long long sn_len = sig_get_sn_len_bytes();
    unsigned char *pk = calloc((size_t)pk_len, 1);
    unsigned char *sk = calloc((size_t)sk_len, 1);
    unsigned char *sn = calloc((size_t)sn_len, 1);
    unsigned char msg[64];
    unsigned long long out_pk = pk_len, out_sk = sk_len, out_sn = sn_len;
    int rc;

    if (!pk || !sk || !sn) {
        fprintf(stderr, "probe: allocation failed\n");
        return 2;
    }
    for (size_t i = 0; i < sizeof msg; i++) {
        msg[i] = (unsigned char)(0x30u + (i & 0x3fu));
    }

    init_probe_drng();
    rc = sig_keygen(pk, &out_pk, sk, &out_sk);
    printf("keygen rc=%d pk_len=%llu sk_len=%llu\n", rc, out_pk, out_sk);
    if (rc != 0) return 3;

    rc = sig_sign(sk, out_sk, msg, sizeof msg, sn, &out_sn);
    printf("sign rc=%d sn_len=%llu\n", rc, out_sn);
    if (rc != 0) return 4;

    rc = sig_verify(pk, out_pk, sn, out_sn, msg, sizeof msg);
    printf("positive_verify rc=%d (expected 0)\n", rc);
    if (rc != 0) return 5;

    sn[0] ^= 1u;
    rc = sig_verify(pk, out_pk, sn, out_sn, msg, sizeof msg);
    printf("bitflip_verify rc=%d (expected nonzero)\n", rc);
    if (rc == 0) return 6;
    sn[0] ^= 1u;

    sn[0] = 0xff;
    sn[1] = 0xff;
    rc = sig_verify(pk, out_pk, sn, out_sn, msg, sizeof msg);
    printf("noncanonical_verify rc=%d (expected nonzero)\n", rc);
    if (rc == 0) return 7;

    rc = sig_verify(pk, out_pk, sn, out_sn - 1, msg, sizeof msg);
    printf("bad_length_verify rc=%d (expected nonzero)\n", rc);
    if (rc == 0) return 8;

    free(sn);
    free(sk);
    free(pk);
    return 0;
}
