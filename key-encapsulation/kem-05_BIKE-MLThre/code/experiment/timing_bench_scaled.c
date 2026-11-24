#define _GNU_SOURCE
#include <errno.h>
#include <inttypes.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "defs.h"
#include "types.h"
#include "kem.h"
#include "ntl.h"
#include "conversions.h"
#include "decode_ml.h"
#include "FromNIST/rng.h"

enum sample_kind {
    SAMPLE_ZERO = 0,
    SAMPLE_ONE_BIT = 1,
    SAMPLE_PAIR = 2,
    SAMPLE_VALID = 3,
    SAMPLE_RANDOM = 4,
    SAMPLE_DENSE = 5
};

typedef struct sample {
    uint8_t c0[R_SIZE];
    uint8_t c1[ELL_SIZE];
    uint32_t weight;
    uint32_t auto1;
    uint32_t auto2;
    uint32_t pos_a;
    uint32_t pos_b;
    uint32_t distance;
    uint8_t kind;
    uint8_t valid_ss_match;
} sample_t;

typedef struct measurement {
    uint64_t ns;
    uint64_t cycles;
    uint32_t status;
} measurement_t;

static uint64_t splitmix64(uint64_t *state)
{
    uint64_t z = (*state += UINT64_C(0x9e3779b97f4a7c15));
    z = (z ^ (z >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
    z = (z ^ (z >> 27)) * UINT64_C(0x94d049bb133111eb);
    return z ^ (z >> 31);
}

static uint32_t random_below(uint64_t *state, uint32_t n)
{
    return (uint32_t)(splitmix64(state) % n);
}

static void random_bytes_local(uint8_t *buf, size_t n, uint64_t *state)
{
    size_t i;
    for (i = 0; i < n; i++)
        buf[i] = (uint8_t)splitmix64(state);
}

static void set_bit(uint8_t *bits, uint32_t pos)
{
    bits[pos >> 3] ^= (uint8_t)(1U << (pos & 7U));
}

static int test_bit(const uint8_t *bits, uint32_t pos)
{
    return (bits[pos >> 3] >> (pos & 7U)) & 1U;
}

static uint32_t bit_weight_dense(const uint8_t *bits, uint32_t nbits)
{
    uint32_t i, w = 0;
    for (i = 0; i < nbits; i++)
        w += bits[i] & 1U;
    return w;
}

static void exact_syndrome(uint8_t sbits[R_BITS], const uint8_t c0[R_SIZE],
                           const sk_t *sk)
{
    uint8_t s0[R_SIZE] = {0};
    uint8_t linear[R_BITS] = {0};
    ntl_mod_mul(s0, sk->val0, c0);
    convertByteToBinary(linear, s0, R_BITS);
    transpose(sbits, linear);
}

static uint32_t cyclic_autocorrelation(const uint8_t *bits, uint32_t n,
                                       uint32_t shift)
{
    uint32_t i, count = 0;
    for (i = 0; i < n; i++)
        count += (bits[i] & 1U) & (bits[(i + shift) % n] & 1U);
    return count;
}

static uint32_t circular_distance(uint32_t a, uint32_t b, uint32_t n)
{
    uint32_t d = a > b ? a - b : b - a;
    return d < n - d ? d : n - d;
}

static uint64_t hash_bytes64(const uint8_t *p, size_t n)
{
    uint64_t h = UINT64_C(1469598103934665603);
    size_t i;
    for (i = 0; i < n; i++) {
        h ^= p[i];
        h *= UINT64_C(1099511628211);
    }
    return h;
}

static int cmp_u64(const void *a, const void *b)
{
    uint64_t x = *(const uint64_t *)a;
    uint64_t y = *(const uint64_t *)b;
    return (x > y) - (x < y);
}

static uint64_t now_ns(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC_RAW, &ts) != 0) {
        perror("clock_gettime");
        exit(2);
    }
    return (uint64_t)ts.tv_sec * UINT64_C(1000000000) + (uint64_t)ts.tv_nsec;
}

static uint64_t read_cycles(void)
{
#if defined(__x86_64__) || defined(__i386__)
    uint32_t lo, hi;
    __asm__ volatile("lfence\n\trdtsc\n\t" : "=a"(lo), "=d"(hi) :: "memory");
    return ((uint64_t)hi << 32) | lo;
#else
    return now_ns();
#endif
}

static void pin_cpu(void)
{
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(0, &set);
    if (sched_setaffinity(0, sizeof(set), &set) != 0)
        fprintf(stderr, "warning: could not pin to cpu0: %s\n", strerror(errno));
}

static void init_sample(sample_t *s, uint8_t kind, const uint8_t c0[R_SIZE],
                        const uint8_t c1[ELL_SIZE], const sk_t *sk,
                        uint32_t pos_a, uint32_t pos_b)
{
    uint8_t sbits[R_BITS] = {0};
    memset(s, 0, sizeof(*s));
    s->kind = kind;
    memcpy(s->c0, c0, R_SIZE);
    memcpy(s->c1, c1, ELL_SIZE);
    s->pos_a = pos_a;
    s->pos_b = pos_b;
    if (kind == SAMPLE_PAIR)
        s->distance = circular_distance(pos_a, pos_b, R_BITS);
    exact_syndrome(sbits, c0, sk);
    s->weight = bit_weight_dense(sbits, R_BITS);
    s->auto1 = cyclic_autocorrelation(sbits, R_BITS, 1);
    s->auto2 = cyclic_autocorrelation(sbits, R_BITS, 2);
}

static uint32_t env_u32(const char *name, uint32_t fallback)
{
    const char *s = getenv(name);
    char *end = NULL;
    unsigned long v;
    if (!s || !*s)
        return fallback;
    errno = 0;
    v = strtoul(s, &end, 10);
    if (errno || *end || v > UINT32_MAX) {
        fprintf(stderr, "invalid %s=%s\n", name, s);
        exit(2);
    }
    return (uint32_t)v;
}

static int build_samples(sample_t **out, const sk_t *sk, const pk_t *pk,
                         uint32_t pairs_wanted, uint32_t valid_wanted,
                         uint32_t random_wanted, uint32_t dense_wanted)
{
    uint32_t h0_positions[DV];
    uint8_t h0[R_BITS] = {0};
    uint32_t h0_weight = 0, i, j, p = 0, made_pairs = 0;
    uint8_t *pair_seen = NULL;
    uint32_t n_samples, idx = 0;
    uint64_t rng = UINT64_C(0x6a09e667f3bcc909);
    sample_t *samples;

    (void)h0;
    convert2compact(h0_positions, sk->val0);
    h0_weight = DV;
    if (h0_weight != DV) {
        fprintf(stderr, "h0 weight mismatch: %u != %llu\n", h0_weight,
                (unsigned long long)DV);
        return -1;
    }

    if (pairs_wanted > (DV * (DV - 1U)) / 2U) {
        fprintf(stderr, "pairs_wanted exceeds full pair universe\n");
        return -1;
    }
    n_samples = 1U + DV + pairs_wanted + valid_wanted + random_wanted +
                dense_wanted;
    samples = calloc(n_samples, sizeof(*samples));
    if (!samples)
        return -1;

    {
        uint8_t c0[R_SIZE] = {0}, c1[ELL_SIZE] = {0};
        init_sample(&samples[idx++], SAMPLE_ZERO, c0, c1, sk, UINT32_MAX,
                    UINT32_MAX);
    }

    for (i = 0; i < DV; i++) {
        uint8_t c0[R_SIZE] = {0}, c1[ELL_SIZE] = {0};
        set_bit(c0, h0_positions[i]);
        init_sample(&samples[idx++], SAMPLE_ONE_BIT, c0, c1, sk,
                    h0_positions[i], UINT32_MAX);
    }

    pair_seen = calloc((size_t)DV * DV, 1);
    if (!pair_seen) {
        free(samples);
        return -1;
    }
    while (made_pairs < pairs_wanted) {
        uint8_t c0[R_SIZE] = {0}, c1[ELL_SIZE] = {0};
        i = random_below(&rng, DV);
        j = random_below(&rng, DV);
        if (i == j || pair_seen[(size_t)i * DV + j])
            continue;
        pair_seen[(size_t)i * DV + j] = 1;
        pair_seen[(size_t)j * DV + i] = 1;
        set_bit(c0, h0_positions[i]);
        set_bit(c0, h0_positions[j]);
        init_sample(&samples[idx++], SAMPLE_PAIR, c0, c1, sk,
                    h0_positions[i], h0_positions[j]);
        made_pairs++;
    }
    free(pair_seen);

    for (i = 0; i < valid_wanted; i++) {
        uint8_t ct[R_SIZE + ELL_SIZE] = {0}, ss[ELL_SIZE] = {0};
        uint8_t dec_ss[ELL_SIZE] = {0};
        if (crypto_kem_enc(ct, ss, (const uint8_t *)pk) != 0) {
            free(samples);
            return -1;
        }
        crypto_kem_dec(dec_ss, ct, (const uint8_t *)sk);
        init_sample(&samples[idx], SAMPLE_VALID, ct, ct + R_SIZE, sk,
                    UINT32_MAX, UINT32_MAX);
        samples[idx].valid_ss_match = memcmp(ss, dec_ss, ELL_SIZE) == 0;
        idx++;
    }

    for (i = 0; i < random_wanted; i++) {
        uint8_t c0[R_SIZE] = {0}, c1[ELL_SIZE] = {0};
        p = 1U + random_below(&rng, 20U);
        for (j = 0; j < R_BITS; j++)
            if (random_below(&rng, 1000U) < p)
                set_bit(c0, j);
        random_bytes_local(c1, ELL_SIZE, &rng);
        init_sample(&samples[idx++], SAMPLE_RANDOM, c0, c1, sk, UINT32_MAX,
                    UINT32_MAX);
    }

    for (i = 0; i < dense_wanted; i++) {
        uint8_t c0[R_SIZE] = {0}, c1[ELL_SIZE] = {0};
        p = 20U + random_below(&rng, 180U);
        for (j = 0; j < R_BITS; j++)
            if (random_below(&rng, 1000U) < p)
                set_bit(c0, j);
        random_bytes_local(c1, ELL_SIZE, &rng);
        init_sample(&samples[idx++], SAMPLE_DENSE, c0, c1, sk, UINT32_MAX,
                    UINT32_MAX);
    }

    fprintf(stderr,
            "samples=%u zero=1 one_bit=%u pair=%u valid=%u random=%u dense=%u full_pair_universe=%u h0_weight=%u\n",
            idx, (unsigned)DV, made_pairs, valid_wanted, random_wanted,
            dense_wanted, (unsigned)((DV * (DV - 1U)) / 2U), h0_weight);
    *out = samples;
    return (int)idx;
}

int main(int argc, char **argv)
{
    const uint32_t reps = argc > 1 ? (uint32_t)strtoul(argv[1], NULL, 10) : 7U;
    const char *out_path = argc > 2 ? argv[2] : "timing_rows.csv";
    const uint32_t key_seed_byte = env_u32("BIKE_KEY_SEED", 0x42U) & 0xffU;
    const uint32_t pairs_wanted = env_u32("BIKE_PAIRS", (DV * (DV - 1U)) / 2U);
    const uint32_t valid_wanted = env_u32("BIKE_VALID", 64U);
    const uint32_t random_wanted = env_u32("BIKE_RANDOM", 128U);
    const uint32_t dense_wanted = env_u32("BIKE_DENSE", 128U);
    uint8_t seed[48];
    uint8_t pk_bytes[sizeof(pk_t)];
    uint8_t sk_bytes[sizeof(sk_t)];
    uint8_t ss[ELL_SIZE] = {0};
    pk_t *pk = (pk_t *)pk_bytes;
    sk_t *sk = (sk_t *)sk_bytes;
    sample_t *samples = NULL;
    measurement_t *measure = NULL;
    uint32_t *order = NULL;
    int n_samples, r, i;
    uint64_t rng = UINT64_C(0x510e527fade682d1);
    FILE *fp;

    memset(seed, (int)key_seed_byte, sizeof(seed));
    randombytes_init(seed, NULL, 256);
    pin_cpu();

    if (crypto_kem_keypair(pk_bytes, sk_bytes) != 0) {
        fprintf(stderr, "keygen failed\n");
        return 2;
    }
    n_samples = build_samples(&samples, sk, pk, pairs_wanted, valid_wanted,
                              random_wanted, dense_wanted);
    if (n_samples < 0) {
        fprintf(stderr, "sample construction failed\n");
        return 2;
    }
    measure = calloc((size_t)n_samples * reps, sizeof(*measure));
    order = calloc((size_t)n_samples, sizeof(*order));
    if (!measure || !order)
        return 2;

    for (i = 0; i < n_samples; i++)
        order[i] = (uint32_t)i;

    /* Warm the hot paths and the ML policy code. */
    for (i = 0; i < n_samples; i++)
        crypto_kem_dec(ss, (const uint8_t *)samples[i].c0, sk_bytes);

    for (r = 0; r < (int)reps; r++) {
        for (i = n_samples - 1; i > 0; i--) {
            uint32_t a = random_below(&rng, (uint32_t)i + 1U);
            uint32_t tmp = order[i];
            order[i] = order[a];
            order[a] = tmp;
        }
        for (i = 0; i < n_samples; i++) {
            sample_t *s = &samples[order[i]];
            uint8_t ct[R_SIZE + ELL_SIZE] = {0};
            uint64_t c0, c1, status;
            int rc;
            memcpy(ct, s->c0, R_SIZE);
            memcpy(ct + R_SIZE, s->c1, ELL_SIZE);
            c0 = read_cycles();
            {
                uint64_t t0 = now_ns();
                rc = crypto_kem_dec(ss, ct, sk_bytes);
                status = now_ns() - t0;
            }
            c1 = read_cycles();
            measure[(size_t)r * n_samples + order[i]].ns = status;
            measure[(size_t)r * n_samples + order[i]].cycles = c1 - c0;
            measure[(size_t)r * n_samples + order[i]].status = (uint32_t)rc;
        }
    }

    fp = fopen(out_path, "w");
    if (!fp) {
        perror(out_path);
        return 2;
    }
    fprintf(fp,
            "repr,sample_id,kind,pos_a,pos_b,distance,syndrome_weight,"
            "autocorr_1,autocorr_2,valid_ss_match,dec_status,ns,cycles\n");
    for (r = 0; r < (int)reps; r++) {
        for (i = 0; i < n_samples; i++) {
            const sample_t *s = &samples[i];
            const measurement_t *m = &measure[(size_t)r * n_samples + i];
            fprintf(fp,
                    "%d,%d,%u,%" PRIu32 ",%" PRIu32 ",%" PRIu32 ",%" PRIu32
                    ",%" PRIu32 ",%" PRIu32 ",%u,%u,%" PRIu64 ",%" PRIu64 "\n",
                    r, i, (uint32_t)s->kind, s->pos_a, s->pos_b,
                    s->distance, s->weight, s->auto1, s->auto2,
                    (uint32_t)s->valid_ss_match, m->status, m->ns, m->cycles);
        }
    }
    fclose(fp);

    printf("{{\n");
    printf("  \"security_bits\": %u,\n", (unsigned)BIKE_SECURITY_BITS);
    printf("  \"r_bits\": %llu,\n", (unsigned long long)R_BITS);
    printf("  \"dv\": %llu,\n", (unsigned long long)DV);
    printf("  \"t1\": %llu,\n", (unsigned long long)T1);
    printf("  \"ell_bytes\": %llu,\n", (unsigned long long)ELL_SIZE);
    printf("  \"sk_bytes\": %zu,\n", sizeof(sk_t));
    printf("  \"pk_bytes\": %zu,\n", sizeof(pk_t));
    printf("  \"ct_bytes\": %llu,\n", (unsigned long long)(R_SIZE + ELL_SIZE));
    printf("  \"samples\": %d,\n", n_samples);
    printf("  \"reps\": %u,\n", reps);
    printf("  \"key_seed\": \"");
    for (i = 0; i < 48; i++)
        printf("%02x", seed[i]);
    printf("\",\n");
    printf("  \"pk_fnv64\": \"%016" PRIx64 "\",\n",
           hash_bytes64(pk_bytes, sizeof(pk_t)));
    printf("  \"sk_fnv64\": \"%016" PRIx64 "\",\n",
           hash_bytes64(sk_bytes, sizeof(sk_t)));
    printf("  \"pinned_cpu\": 0\n");
    printf("}}\n");

    free(samples);
    free(measure);
    free(order);
    return 0;
}
