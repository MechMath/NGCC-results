#define _GNU_SOURCE
#include <errno.h>
#include <inttypes.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "api.h"
#include "kem.h"
#include "FromNIST/rng.h"

#ifndef VARIANT
#define VARIANT "unknown"
#endif

enum {
    KEYS = 4,
    CLASSES = 6,
    REPS = 128,
    WARMUPS = 8
};

static inline uint64_t rdtscp_now(void)
{
    uint32_t aux;
    return __builtin_ia32_rdtscp(&aux);
}

static void init_drbg(uint32_t profile, uint32_t key)
{
    unsigned char seed[48];
    for (uint32_t i = 0; i < sizeof(seed); i++) {
        seed[i] = (unsigned char)(0x5aU ^ (i * 17U) ^
                                  (profile << 4) ^ key);
    }
    randombytes_init(seed, NULL, 256);
}

static void print_hex32(const unsigned char *x, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        printf("%02x", x[i]);
    }
}

static int pin_cpu(int cpu)
{
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    return sched_setaffinity(0, sizeof(set), &set);
}

int main(int argc, char **argv)
{
    const int cpu = (argc > 1) ? atoi(argv[1]) : 2;
    const unsigned pk_len = CRYPTO_PUBLICKEYBYTES;
    const unsigned sk_len = CRYPTO_SECRETKEYBYTES;
    const unsigned ct_len = CRYPTO_CIPHERTEXTBYTES;
    const unsigned ss_len = CRYPTO_BYTES;
    const uint32_t profile =
#if defined(BIKE_SECURITY_256) || SECURITY_BITS == 256
        256;
#else
        128;
#endif

    if (pin_cpu(cpu) != 0) {
        fprintf(stderr, "pin_cpu(%d): %s\n", cpu, strerror(errno));
        return 2;
    }

    unsigned char *pk = calloc(1, pk_len);
    unsigned char *sk = calloc(1, sk_len);
    unsigned char *ct = calloc(1, ct_len);
    unsigned char *ss = calloc(1, ss_len);
    unsigned char *ss1 = calloc(1, ss_len);
    unsigned char *choices = calloc(CLASSES, ct_len);
    if (!pk || !sk || !ct || !ss || !ss1 || !choices) {
        return 3;
    }

    printf("variant,profile,key,ct_class,rep,rdtsc,ns,ret,match,ct_fnv1a64\n");
    for (uint32_t key = 0; key < KEYS; key++) {
        init_drbg(profile, key);
        if (crypto_kem_keypair(pk, sk) != 0 ||
            crypto_kem_enc(ct, ss, pk) != 0) {
            fprintf(stderr, "keypair/encaps failed at key=%u\n", key);
            return 4;
        }

        memcpy(choices + 0 * ct_len, ct, ct_len);
        memset(choices + 1 * ct_len, 0, ct_len);
        memcpy(choices + 2 * ct_len, ct, ct_len);
        randombytes(choices + 2 * ct_len, ct_len);
        memcpy(choices + 3 * ct_len, ct, ct_len);
        randombytes(choices + 3 * ct_len + (ct_len - ss_len),
                    ss_len);
        memcpy(choices + 4 * ct_len, ct, ct_len);
        choices[4 * ct_len + (key % (ct_len - ss_len))] ^= 1U;
        memcpy(choices + 5 * ct_len, ct, ct_len);
        randombytes(choices + 5 * ct_len, ct_len);

        for (uint32_t cls = 0; cls < CLASSES; cls++) {
            const unsigned char *chosen = choices + cls * ct_len;
            for (uint32_t w = 0; w < WARMUPS; w++) {
                if (crypto_kem_dec(ss1, chosen, sk) != 0) {
                    fprintf(stderr, "warmup decaps failed\n");
                    return 5;
                }
            }
            for (uint32_t rep = 0; rep < REPS; rep++) {
                struct timespec t0, t1;
                const int rc0 = clock_gettime(CLOCK_MONOTONIC_RAW, &t0);
                const uint64_t c0 = rdtscp_now();
                const int rc = crypto_kem_dec(ss1, chosen, sk);
                const uint64_t c1 = rdtscp_now();
                const int rc1 = clock_gettime(CLOCK_MONOTONIC_RAW, &t1);
                if (rc0 != 0 || rc1 != 0) {
                    return 6;
                }
                const uint64_t ns =
                    ((uint64_t)t1.tv_sec - (uint64_t)t0.tv_sec) * 1000000000ULL +
                    ((uint64_t)t1.tv_nsec - (uint64_t)t0.tv_nsec);
                uint64_t h = UINT64_C(1469598103934665603);
                for (unsigned i = 0; i < ct_len; i++) {
                    h ^= chosen[i];
                    h *= UINT64_C(1099511628211);
                }
                printf("%s,%u,%u,%u,%u,%" PRIu64 ",%" PRIu64
                       ",%d,%d,%016" PRIx64 "\n",
                       VARIANT, profile, key, cls, rep, c1 - c0, ns, rc,
                       rc == 0 && memcmp(ss, ss1, ss_len) == 0, h);
            }
        }
    }

    free(choices);
    free(ss1);
    free(ss);
    free(ct);
    free(sk);
    free(pk);
    return 0;
}
