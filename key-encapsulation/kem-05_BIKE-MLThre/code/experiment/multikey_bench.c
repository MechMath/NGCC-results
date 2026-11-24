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

void recompute_syndrome(uint8_t s[R_BITS], uint32_t pos,
                        const uint32_t h0_compact[DV],
                        const uint32_t h1_compact[DV]);

#define NKEYS 3U
#define NSTRATA 7U
#define PER_STRATUM 48U
#define NSAMPLES (NKEYS * NSTRATA * PER_STRATUM)

static const uint32_t public_weights[NSTRATA] = {8, 16, 32, 64, 128, 256, 512};
static const uint8_t key_bytes[NKEYS] = {0x42, 0x43, 0x44};

typedef struct {
    uint8_t c0[R_SIZE];
    uint8_t c1[ELL_SIZE];
    uint32_t key_id;
    uint32_t stratum;
    uint32_t mask_id;
    uint32_t c0_weight;
    uint32_t syndrome_weight;
} sample_t;

typedef struct {
    uint64_t ns;
    uint64_t cycles;
    uint32_t status;
} measurement_t;

typedef struct {
    uint8_t pk[sizeof(pk_t)];
    uint8_t sk[sizeof(sk_t)];
} key_material_t;

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

static uint64_t hash_bytes64(const uint8_t *p, size_t n)
{
    uint64_t h = UINT64_C(1469598103934665603);
    for (size_t i = 0; i < n; i++) {
        h ^= p[i];
        h *= UINT64_C(1099511628211);
    }
    return h;
}

static int test_bit(const uint8_t *bits, uint32_t pos)
{
    return (bits[pos >> 3] >> (pos & 7U)) & 1U;
}

static void set_bit(uint8_t *bits, uint32_t pos)
{
    bits[pos >> 3] |= (uint8_t)(1U << (pos & 7U));
}

static uint32_t bit_weight_dense(const uint8_t *bits, uint32_t nbits)
{
    uint32_t weight = 0;
    for (uint32_t i = 0; i < nbits; i++)
        weight += bits[i] & 1U;
    return weight;
}

static void exact_syndrome(uint8_t sbits[R_BITS], const uint8_t c0[R_SIZE],
                           const sk_t *sk)
{
    uint8_t product[R_SIZE] = {0};
    uint8_t linear[R_BITS] = {0};
    ntl_mod_mul(product, sk->val0, c0);
    convertByteToBinary(linear, product, R_BITS);
    transpose(sbits, linear);
}

/* Independent support-level oracle: XOR the sparse h0 columns selected by c0. */
static uint32_t sparse_syndrome_weight(const uint8_t c0[R_SIZE],
                                       const uint32_t h0_compact[DV],
                                       const uint32_t h1_compact[DV])
{
    uint8_t sbits[R_BITS];
    memset(sbits, 0, R_BITS);
    for (uint32_t pos = 0; pos < R_BITS; pos++) {
        if (test_bit(c0, pos)) {
            uint32_t adjusted = (pos == 0) ? 0 : R_BITS - pos;
            recompute_syndrome(sbits, adjusted, h0_compact, h1_compact);
        }
    }
    return bit_weight_dense(sbits, R_BITS);
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
    uint32_t lo, hi;
    __asm__ volatile("lfence\n\trdtsc\n\t" : "=a"(lo), "=d"(hi) :: "memory");
    return ((uint64_t)hi << 32) | lo;
}

static void pin_cpu(void)
{
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(0, &set);
    if (sched_setaffinity(0, sizeof(set), &set) != 0) {
        fprintf(stderr, "warning: could not pin to CPU 0: %s\n", strerror(errno));
    }
}

static void make_mask(uint8_t c0[R_SIZE], uint32_t weight, uint64_t *rng)
{
    uint16_t positions[R_BITS];
    memset(c0, 0, R_SIZE);
    for (uint32_t i = 0; i < R_BITS; i++)
        positions[i] = (uint16_t)i;
    for (uint32_t i = 0; i < weight; i++) {
        uint32_t j = i + random_below(rng, R_BITS - i);
        uint16_t tmp = positions[i];
        positions[i] = positions[j];
        positions[j] = tmp;
        set_bit(c0, positions[i]);
    }
}

static int build_samples(sample_t samples[NSAMPLES], key_material_t keys[NKEYS])
{
    uint64_t mask_rng = UINT64_C(0x243f6a8885a308d3);
    uint32_t idx = 0;
    for (uint32_t k = 0; k < NKEYS; k++) {
        uint8_t seed[48];
        sk_t *sk = (sk_t *)keys[k].sk;
        uint32_t h0[DV], h1[DV];
        memset(seed, key_bytes[k], sizeof(seed));
        randombytes_init(seed, NULL, 256);
        if (crypto_kem_keypair(keys[k].pk, keys[k].sk) != 0) {
            fprintf(stderr, "keygen failed for key %u\n", k);
            return -1;
        }
        convert2compact(h0, sk->val0);
        convert2compact(h1, sk->val1);
        for (uint32_t stratum = 0; stratum < NSTRATA; stratum++) {
            for (uint32_t mask_id = 0; mask_id < PER_STRATUM; mask_id++) {
                sample_t *sample = &samples[idx++];
                uint8_t dense[R_BITS];
                memset(sample, 0, sizeof(*sample));
                sample->key_id = k;
                sample->stratum = stratum;
                sample->mask_id = mask_id;
                sample->c0_weight = public_weights[stratum];
                make_mask(sample->c0, sample->c0_weight, &mask_rng);
                exact_syndrome(dense, sample->c0, sk);
                sample->syndrome_weight = bit_weight_dense(dense, R_BITS);
                uint32_t sparse_weight =
                    sparse_syndrome_weight(sample->c0, h0, h1);
                if (sparse_weight != sample->syndrome_weight) {
                    fprintf(stderr,
                            "syndrome oracle validation failed key=%u stratum=%u mask=%u dense=%u sparse=%u\n",
                            k, stratum, mask_id, sample->syndrome_weight,
                            sparse_weight);
                    return -1;
                }
            }
        }
    }
    return (int)idx;
}

int main(int argc, char **argv)
{
    const uint32_t reps = argc > 1 ? (uint32_t)strtoul(argv[1], NULL, 10) : 5U;
    const char *out_path = argc > 2 ? argv[2] : "multikey_rows.csv";
    sample_t samples[NSAMPLES];
    key_material_t keys[NKEYS];
    static measurement_t measure[NSAMPLES * 16U];
    uint32_t order[NSAMPLES];
    uint64_t rng = UINT64_C(0x13198a2e03707344);
    uint8_t ss[ELL_SIZE];
    int n_samples;

    if (reps == 0 || reps > 16U) {
        fprintf(stderr, "reps must be 1..16\n");
        return 2;
    }
    pin_cpu();
    n_samples = build_samples(samples, keys);
    if (n_samples != (int)NSAMPLES)
        return 2;
    for (uint32_t i = 0; i < NSAMPLES; i++)
        order[i] = i;

    /* Warm key material, decoder, and ML policy for every sample. */
    for (uint32_t i = 0; i < NSAMPLES; i++) {
        uint8_t ct[R_SIZE + ELL_SIZE] = {0};
        memcpy(ct, samples[i].c0, R_SIZE);
        memcpy(ct + R_SIZE, samples[i].c1, ELL_SIZE);
        crypto_kem_dec(ss, ct, keys[samples[i].key_id].sk);
    }

    for (uint32_t r = 0; r < reps; r++) {
        for (uint32_t i = NSAMPLES - 1; i > 0; i--) {
            uint32_t j = random_below(&rng, i + 1U);
            uint32_t tmp = order[i];
            order[i] = order[j];
            order[j] = tmp;
        }
        for (uint32_t p = 0; p < NSAMPLES; p++) {
            uint32_t i = order[p];
            sample_t *sample = &samples[i];
            uint8_t ct[R_SIZE + ELL_SIZE] = {0};
            uint64_t c0, c1;
            memcpy(ct, sample->c0, R_SIZE);
            memcpy(ct + R_SIZE, sample->c1, ELL_SIZE);
            c0 = read_cycles();
            uint64_t t0 = now_ns();
            int rc = crypto_kem_dec(ss, ct, keys[sample->key_id].sk);
            uint64_t elapsed = now_ns() - t0;
            c1 = read_cycles();
            measure[(size_t)r * NSAMPLES + i].ns = elapsed;
            measure[(size_t)r * NSAMPLES + i].cycles = c1 - c0;
            measure[(size_t)r * NSAMPLES + i].status = (uint32_t)rc;
        }
    }

    FILE *fp = fopen(out_path, "w");
    if (!fp) {
        perror(out_path);
        return 2;
    }
    fprintf(fp,
            "repr,sample_id,key_id,stratum,mask_id,c0_weight,syndrome_weight,"
            "dec_status,ns,cycles\n");
    for (uint32_t r = 0; r < reps; r++) {
        for (uint32_t i = 0; i < NSAMPLES; i++) {
            const sample_t *sample = &samples[i];
            const measurement_t *m = &measure[(size_t)r * NSAMPLES + i];
            fprintf(fp,
                    "%" PRIu32 ",%" PRIu32 ",%" PRIu32 ",%" PRIu32
                    ",%" PRIu32 ",%" PRIu32 ",%" PRIu32 ",%" PRIu32
                    ",%" PRIu64 ",%" PRIu64 "\n",
                    r, i, sample->key_id, sample->stratum, sample->mask_id,
                    sample->c0_weight, sample->syndrome_weight, m->status,
                    m->ns, m->cycles);
        }
    }
    fclose(fp);

    printf("{\n");
    printf("  \"security_bits\": %u,\n", (unsigned)BIKE_SECURITY_BITS);
    printf("  \"r_bits\": %llu,\n", (unsigned long long)R_BITS);
    printf("  \"dv\": %llu,\n", (unsigned long long)DV);
    printf("  \"t1\": %llu,\n", (unsigned long long)T1);
    printf("  \"keys\": %u,\n", NKEYS);
    printf("  \"strata\": %u,\n", NSTRATA);
    printf("  \"per_stratum\": %u,\n", PER_STRATUM);
    printf("  \"samples\": %u,\n", NSAMPLES);
    printf("  \"reps\": %u,\n", reps);
    printf("  \"public_weights\": [8,16,32,64,128,256,512],\n");
    printf("  \"key_seeds\": [");
    for (uint32_t k = 0; k < NKEYS; k++)
        printf("%s\"%02x-repeated-48\"", k ? "," : "", key_bytes[k]);
    printf("],\n");
    for (uint32_t k = 0; k < NKEYS; k++) {
        printf("  \"key_%u_pk_fnv64\": \"%016" PRIx64 "\",\n",
               k, hash_bytes64(keys[k].pk, sizeof(pk_t)));
        printf("  \"key_%u_sk_fnv64\": \"%016" PRIx64 "\"%s\n",
               k, hash_bytes64(keys[k].sk, sizeof(sk_t)), k + 1U < NKEYS ? "," : "");
    }
    printf("}\n");
    return 0;
}
