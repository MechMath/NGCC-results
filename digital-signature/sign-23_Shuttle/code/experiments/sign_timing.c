#define _POSIX_C_SOURCE 200809L

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "SIG_AlgorithmInstance.h"
#include "drng.h"

DRNG_ctx drng_algorithm;
extern uint32_t shuttle_last_sign_attempts;

static void fill_nonce(unsigned char *nonce, size_t n, uint32_t domain,
                       uint32_t key_id, uint32_t sample_id)
{
    for (size_t i = 0; i < n; ++i) {
        uint32_t x = domain ^ (key_id * 0x9e3779b9u) ^
                     (sample_id * 0x85ebca6bu) ^ (uint32_t)i;
        x ^= x >> 16;
        x *= 0x7feb352du;
        x ^= x >> 15;
        nonce[i] = (unsigned char)(x >> 24);
    }
}

static uint64_t now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

int main(int argc, char **argv)
{
    const uint32_t keys = (argc > 1) ? (uint32_t)strtoul(argv[1], 0, 10) : 8;
    const uint32_t samples =
        (argc > 2) ? (uint32_t)strtoul(argv[2], 0, 10) : 200;
    const unsigned long long pk_len0 = sig_get_pk_len_bytes();
    const unsigned long long sk_len0 = sig_get_sk_len_bytes();
    const unsigned long long sn_len0 = sig_get_sn_len_bytes();
    unsigned char *pks = calloc((size_t)keys * (size_t)pk_len0, 1);
    unsigned char *sks = calloc((size_t)keys * (size_t)sk_len0, 1);
    unsigned char *sn = calloc((size_t)sn_len0, 1);
    unsigned char nonce[32];
    unsigned char msg[56];

    if (!pks || !sks || !sn) {
        fprintf(stderr, "allocation failure\n");
        return 2;
    }
    memset(msg, 0x5a, sizeof msg);
    puts("key_id,sample_id,attempts,wall_ns,rc,verify_rc");

    for (uint32_t key_id = 0; key_id < keys; ++key_id) {
        unsigned char *pk = pks + (size_t)key_id * (size_t)pk_len0;
        unsigned char *sk = sks + (size_t)key_id * (size_t)sk_len0;
        unsigned long long pk_len = pk_len0;
        unsigned long long sk_len = sk_len0;
        fill_nonce(nonce, sizeof nonce, 0x4b455947u, key_id, 0);
        if (init_random_number(&drng_algorithm, nonce, sizeof nonce) != 0)
            return 3;
        int rc = sig_keygen(pk, &pk_len, sk, &sk_len);
        if (rc != 0) {
            fprintf(stderr, "keygen key=%u rc=%d\n", key_id, rc);
            return 4;
        }
    }

    /* Interleave keys after key generation so machine drift is not
     * confounded with the fixed key. */
    for (uint32_t sample_id = 0; sample_id < samples; ++sample_id) {
        for (uint32_t pos = 0; pos < keys; ++pos) {
            uint32_t key_id = (pos + sample_id) % keys;
            unsigned char *pk = pks + (size_t)key_id * (size_t)pk_len0;
            unsigned char *sk = sks + (size_t)key_id * (size_t)sk_len0;
            unsigned long long pk_len = pk_len0;
            unsigned long long sk_len = sk_len0;
            unsigned long long sn_len = sn_len0;
            int rc;
            fill_nonce(nonce, sizeof nonce, 0x5349474eu, key_id, sample_id);
            if (init_random_number(&drng_algorithm, nonce, sizeof nonce) != 0)
                return 3;
            uint64_t t0 = now_ns();
            rc = sig_sign(sk, sk_len, msg, sizeof msg, sn, &sn_len);
            uint64_t t1 = now_ns();
            int vr = (rc == 0)
                         ? sig_verify(pk, pk_len, sn, sn_len, msg,
                                      sizeof msg)
                         : -99;
            printf("%u,%u,%u,%llu,%d,%d\n", key_id, sample_id,
                   shuttle_last_sign_attempts,
                   (unsigned long long)(t1 - t0), rc, vr);
            if (rc != 0 || vr != 0) {
                fprintf(stderr,
                        "signature failure key=%u sample=%u sign=%d verify=%d\n",
                        key_id, sample_id, rc, vr);
                return 5;
            }
        }
    }

    free(sn);
    free(sks);
    free(pks);
    return 0;
}
