#define _POSIX_C_SOURCE 200809L

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "KEM_AlgorithmInstance.h"
#include "api.h"
#include "drng.h"

#ifdef REFERENCE_PROBE
#include "mlthre_runtime_sampling.h"
#endif

#ifdef REFERENCE_PROBE
#define C0_BYTES R_SIZE
#else
#define C0_BYTES R_BYTES
#endif

DRNG_ctx drng_algorithm;

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

static uint64_t now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
    return (uint64_t)ts.tv_sec * UINT64_C(1000000000) +
           (uint64_t)ts.tv_nsec;
}

int main(int argc, char **argv)
{
    if (argc != 6) {
        fprintf(stderr,
                "usage: %s NAME MODE MUTATIONS REPETITIONS KEY_INDEX\n",
                argv[0]);
        return 2;
    }

    const char *name = argv[1];
    const char *mode = argv[2];
    size_t mutations = (size_t)strtoull(argv[3], NULL, 10);
    size_t reps = (size_t)strtoull(argv[4], NULL, 10);
    uint32_t key_index = (uint32_t)strtoul(argv[5], NULL, 10);
    const size_t pk_len = (size_t)kem_get_pk_len_bytes();
    const size_t sk_len = (size_t)kem_get_sk_len_bytes();
    const size_t ct_len = (size_t)kem_get_ct_len_bytes();
    const size_t ss_len = (size_t)kem_get_ss_len_bytes();
    unsigned char *pk = calloc(pk_len, 1);
    unsigned char *sk = calloc(sk_len, 1);
    unsigned char *base_ct = calloc(ct_len, 1);
    unsigned char *mutated_ct = calloc(ct_len, 1);
    unsigned char *expected_ss = calloc(ss_len, 1);
    unsigned char *actual_ss = calloc(ss_len, 1);
    unsigned long long out_len = ss_len;
    DRNG_ctx seed_drng;

    if (pk == NULL || sk == NULL || base_ct == NULL ||
        mutated_ct == NULL || expected_ss == NULL || actual_ss == NULL) {
        return 3;
    }
    if (init_seed(&seed_drng, key_index) != 0) {
        return 4;
    }
#ifdef REFERENCE_PROBE
    if (strcmp(mode, "support") == 0 &&
        mlthre_runtime_sampling_init("support", 1, 0) != 0) {
        return 5;
    }
#endif
    {
        unsigned char seed[64];
        if (get_random_number(&seed_drng, seed, sizeof(seed) * 8) != 0 ||
            init_random_number(&drng_algorithm, seed, sizeof(seed)) != 0) {
            return 4;
        }
    }
    if (kem_keygen(pk, &(unsigned long long){pk_len},
                   sk, &(unsigned long long){sk_len}) != 0 ||
        kem_enc(pk, pk_len, expected_ss, &out_len,
                base_ct, &(unsigned long long){ct_len}) != 0) {
        return 4;
    }
    memcpy(mutated_ct, base_ct, ct_len);

    if (strcmp(mode, "support") == 0) {
        (void)kem_dec(sk, sk_len, base_ct, ct_len, actual_ss, &out_len);
        fprintf(stderr, "base_ciphertext_recovered=%d\n",
                memcmp(expected_ss, actual_ss, ss_len) == 0);
#ifdef REFERENCE_PROBE
        printf("key,true_bit,recovered,ss_prefix\n");
        size_t tested = 0;
        for (size_t bit = 0; bit < C0_BYTES * 8U; bit++) {
            int in_support =
                mlthre_runtime_sampling_true_error_bit((uint32_t)bit);
            if (in_support < 0) {
                return 5;
            }
            if (in_support == 0) {
                continue;
            }
            memcpy(mutated_ct, base_ct, ct_len);
            mutated_ct[bit / 8] ^= (unsigned char)(1U << (bit % 8));
            (void)kem_dec(sk, sk_len, mutated_ct, ct_len,
                          actual_ss, &out_len);
            uint64_t prefix = 0;
            memcpy(&prefix, actual_ss, ss_len < sizeof(prefix) ?
                   ss_len : sizeof(prefix));
            printf("%u,%zu,%d,%016" PRIx64 "\n", key_index, bit,
                   memcmp(expected_ss, actual_ss, ss_len) == 0, prefix);
            tested++;
        }
        mlthre_runtime_sampling_close();
        fprintf(stderr, "tested %zu true-error positions\n", tested);
#else
        const char *positions_path = getenv("MUTATION_POSITIONS");
        FILE *positions = positions_path == NULL ? NULL :
            fopen(positions_path, "r");
        if (positions == NULL) {
            fprintf(stderr, "MUTATION_POSITIONS must name a bit-position file\n");
            return 5;
        }
        printf("key,true_bit,recovered,ss_prefix\n");
        unsigned long bit;
        size_t tested = 0;
        while (fscanf(positions, "%lu", &bit) == 1) {
            if (bit >= C0_BYTES * 8U) {
                fclose(positions);
                return 5;
            }
            memcpy(mutated_ct, base_ct, ct_len);
            mutated_ct[bit / 8] ^= (unsigned char)(1U << (bit % 8));
            (void)kem_dec(sk, sk_len, mutated_ct, ct_len,
                          actual_ss, &out_len);
            uint64_t prefix = 0;
            memcpy(&prefix, actual_ss, ss_len < sizeof(prefix) ?
                   ss_len : sizeof(prefix));
            printf("%u,%lu,%d,%016" PRIx64 "\n", key_index, bit,
                   memcmp(expected_ss, actual_ss, ss_len) == 0, prefix);
            tested++;
        }
        fclose(positions);
        fprintf(stderr, "tested %zu listed positions\n", tested);
#endif
    } else if (strcmp(mode, "diagnostic") == 0) {
#ifdef REFERENCE_PROBE
        if (mlthre_runtime_sampling_init("mutation", mutations, 0) != 0) {
            return 5;
        }
        for (size_t i = 0; i < mutations; i++) {
            size_t bit = (i * 4051U + key_index * 65537U) % (C0_BYTES * 8U);
            memcpy(mutated_ct, base_ct, ct_len);
            mutated_ct[bit / 8] ^= (unsigned char)(1U << (bit % 8));
            mlthre_runtime_sampling_set_sample(0, (uint32_t)i,
                                               (uint32_t)i + 1);
            (void)kem_dec(sk, sk_len, mutated_ct, ct_len,
                          actual_ss, &out_len);
        }
        mlthre_runtime_sampling_close();
#else
        (void)name;
        fprintf(stderr, "diagnostic mode unavailable: optimized build\n");
        return 5;
#endif
    } else if (strcmp(mode, "timing") == 0) {
        printf("implementation,key,mutation,repetition,nanoseconds,recovered,ss_prefix\n");
        for (size_t r = 0; r < reps; r++) {
            for (size_t i = 0; i < mutations; i++) {
                size_t bit = (i * 4051U + key_index * 65537U) %
                             (C0_BYTES * 8U);
                memcpy(mutated_ct, base_ct, ct_len);
                mutated_ct[bit / 8] ^= (unsigned char)(1U << (bit % 8));
                uint64_t begin = now_ns();
                (void)kem_dec(sk, sk_len, mutated_ct, ct_len,
                              actual_ss, &out_len);
                uint64_t elapsed = now_ns() - begin;
                uint64_t prefix = 0;
                memcpy(&prefix, actual_ss, ss_len < sizeof(prefix) ?
                       ss_len : sizeof(prefix));
                printf("%s,%u,%zu,%zu,%" PRIu64 ",%d,%016" PRIx64 "\n",
                       name, key_index, i, r, elapsed,
                       memcmp(expected_ss, actual_ss, ss_len) == 0,
                       prefix);
            }
        }
    } else {
        fprintf(stderr, "unknown mode %s\n", mode);
        return 2;
    }

    free(actual_ss);
    free(expected_ss);
    free(mutated_ct);
    free(base_ct);
    free(sk);
    free(pk);
    return 0;
}
