#define _POSIX_C_SOURCE 200809L

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "KEM_AlgorithmInstance.h"
#include "drng.h"

#ifdef REFERENCE_PROBE
#include "mlthre_runtime_sampling.h"
#endif

DRNG_ctx drng_algorithm;

static uint64_t xorshift64(uint64_t *state)
{
    uint64_t x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    return x;
}

static int init_seed(DRNG_ctx *seed_drng, uint32_t key_index)
{
    unsigned char nonce[64];
    for (size_t i = 0; i < sizeof(nonce); i += 4) {
        memcpy(nonce + i, "seed", 4);
    }
    memcpy(nonce + sizeof(nonce) - sizeof(key_index), &key_index,
           sizeof(key_index));
    return init_random_number(seed_drng, nonce, sizeof(nonce));
}

static int make_case(unsigned char *pk, unsigned char *sk,
                     unsigned char **cts, size_t ct_len, size_t samples,
                     uint32_t key_index)
{
    DRNG_ctx seed_drng;
    unsigned char seed[64];
    unsigned long long pk_len = kem_get_pk_len_bytes();
    unsigned long long sk_len = kem_get_sk_len_bytes();
    uint64_t rng = UINT64_C(0x9e3779b97f4a7c15);

    if (init_seed(&seed_drng, key_index) != 0 ||
        get_random_number(&seed_drng, seed, sizeof(seed) * 8) != 0) {
        return -1;
    }
    if (init_random_number(&drng_algorithm, seed, sizeof(seed)) != 0) {
        return -1;
    }
    if (kem_keygen(pk, &pk_len, sk, &sk_len) != 0) {
        return -1;
    }

    for (size_t i = 0; i < samples; i++) {
        for (size_t j = 0; j < ct_len; j += 8) {
            uint64_t v = xorshift64(&rng);
            size_t take = ct_len - j < 8 ? ct_len - j : 8;
            memcpy(cts[i] + j, &v, take);
        }
    }
    return 0;
}

static uint64_t now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
    return (uint64_t)ts.tv_sec * UINT64_C(1000000000) +
           (uint64_t)ts.tv_nsec;
}

int main(int argc, char **argv)
{
    if (argc != 5 && argc != 6) {
        fprintf(stderr,
                "usage: %s NAME MODE SAMPLES REPETITIONS [KEY_INDEX]\n",
                argv[0]);
        return 2;
    }

    const char *name = argv[1];
    const char *mode = argv[2];
    size_t samples = (size_t)strtoull(argv[3], NULL, 10);
    size_t reps = (size_t)strtoull(argv[4], NULL, 10);
    uint32_t key_index = argc == 6 ?
                         (uint32_t)strtoul(argv[5], NULL, 10) : 0;
    const size_t ct_len = (size_t)kem_get_ct_len_bytes();
    const size_t sk_len = (size_t)kem_get_sk_len_bytes();
    const size_t pk_len = (size_t)kem_get_pk_len_bytes();
    const size_t ss_len = (size_t)kem_get_ss_len_bytes();
    unsigned char *pk = calloc(pk_len, 1);
    unsigned char *sk = calloc(sk_len, 1);
    unsigned char *ss = calloc(ss_len, 1);
    unsigned char **cts = calloc(samples, sizeof(*cts));

    if (pk == NULL || sk == NULL || ss == NULL || cts == NULL) {
        return 3;
    }
    for (size_t i = 0; i < samples; i++) {
        cts[i] = calloc(ct_len, 1);
        if (cts[i] == NULL) {
            return 3;
        }
    }
    if (make_case(pk, sk, cts, ct_len, samples, key_index) != 0) {
        return 4;
    }

#ifdef REFERENCE_PROBE
    if (strcmp(mode, "diagnostic") == 0) {
        if (mlthre_runtime_sampling_init("probe", samples, 0) != 0) {
            return 5;
        }
    }
#else
    if (strcmp(mode, "diagnostic") == 0) {
        fprintf(stderr, "diagnostic mode unavailable: optimized build\n");
        return 5;
    }
#endif

    if (strcmp(mode, "diagnostic") == 0) {
        for (size_t i = 0; i < samples; i++) {
            unsigned long long len = ss_len;
#ifdef REFERENCE_PROBE
            mlthre_runtime_sampling_set_sample(0, (uint32_t)i,
                                               (uint32_t)i + 1);
#endif
            (void)kem_dec(sk, sk_len, cts[i], ct_len, ss, &len);
        }
#ifdef REFERENCE_PROBE
        mlthre_runtime_sampling_close();
#endif
    } else if (strcmp(mode, "timing") == 0) {
        printf("implementation,sample,repetition,nanoseconds,ss_prefix\n");
        for (size_t r = 0; r < reps; r++) {
            for (size_t i = 0; i < samples; i++) {
                unsigned long long len = ss_len;
                uint64_t begin = now_ns();
                (void)kem_dec(sk, sk_len, cts[i], ct_len, ss, &len);
                uint64_t elapsed = now_ns() - begin;
                uint64_t prefix = 0;
                memcpy(&prefix, ss, ss_len < sizeof(prefix) ? ss_len :
                       sizeof(prefix));
                printf("%s,%zu,%zu,%" PRIu64 ",%016" PRIx64 "\n",
                       name, i, r, elapsed, prefix);
            }
        }
    } else {
        fprintf(stderr, "unknown mode %s\n", mode);
        return 2;
    }

    for (size_t i = 0; i < samples; i++) {
        free(cts[i]);
    }
    free(cts);
    free(ss);
    free(sk);
    free(pk);
    return 0;
}
