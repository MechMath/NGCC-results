#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "api.h"
#include "drng.h"
#include "hash.h"
#include "params.h"

DRNG_ctx drng_algorithm;

#define MAX_QUERIES 2400
#define MAX_RETAINED 400

void randombytes(unsigned char *out, unsigned long long outlen)
{
    if (get_random_number(&drng_algorithm, out, outlen * 8) != 0) {
        fprintf(stderr, "randombytes failure\n");
        abort();
    }
}

static uint64_t splitmix64(uint64_t *state)
{
    uint64_t z = (*state += UINT64_C(0x9e3779b97f4a7c15));
    z = (z ^ (z >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
    z = (z ^ (z >> 27)) * UINT64_C(0x94d049bb133111eb);
    return z ^ (z >> 31);
}

static void digest_indices(unsigned int indices[SPX_FORS_TREES],
                           const unsigned char digest[SPX_FORS_MSG_BYTES])
{
    unsigned int offset = 0;
    for (unsigned int i = 0; i < SPX_FORS_TREES; i++) {
        indices[i] = 0;
        for (unsigned int j = 0; j < SPX_FORS_HEIGHT; j++) {
            indices[i] ^= ((digest[offset >> 3] >> (offset & 7)) & 1U) << j;
            offset++;
        }
    }
}

static int write_file(const char *path, const void *data, size_t len)
{
    FILE *f = fopen(path, "wb");
    if (f == NULL) {
        return -1;
    }
    int ok = fwrite(data, 1, len, f) == len && fclose(f) == 0;
    return ok ? 0 : -1;
}

static unsigned long long digest_bytes_to_ull(const unsigned char *in, size_t len)
{
    unsigned long long result = 0;
    for (size_t i = 0; i < len; i++) {
        result = (result << 8) | in[i];
    }
    return result;
}

int main(void)
{
    const char *pk_path = "optimized-pk.bin";
    const char *forged_path = "optimized-forged-signature.bin";
    const char *report_path = "optimized-attack-report.json";
    unsigned char seed[64];
    unsigned char pk[SPX_PK_BYTES];
    unsigned char sk[SPX_SK_BYTES];
    unsigned char *records = calloc(MAX_RETAINED, SPX_BYTES);
    unsigned char *sig = malloc(SPX_BYTES);
    unsigned char *forged = malloc(SPX_BYTES);
    unsigned char digest[SPX_FORS_MSG_BYTES];
    unsigned int indices[SPX_FORS_TREES];
    int representative[SPX_FORS_TREES][1U << SPX_FORS_HEIGHT];
    uint64_t covered_positions[SPX_FORS_TREES] = {0};
    unsigned long long covered = 0;
    unsigned long long total_queries = 0;
    unsigned long long same_instance = 0;
    unsigned long long retained = 0;
    unsigned long long valid_positive_control = 0;
    uint32_t attack_counter = 0;
    uint64_t attack_tree = UINT64_MAX;
    uint32_t attack_leaf = UINT32_MAX;
    unsigned long long attack_trials = 0;

    if (records == NULL || sig == NULL || forged == NULL) {
        fprintf(stderr, "allocation failure\n");
        return 2;
    }
    memset(representative, -1, sizeof(representative));

    for (size_t i = 0; i < sizeof(seed); i++) {
        seed[i] = (unsigned char)(i * 37U + 11U);
    }
    if (init_random_number(&drng_algorithm, seed, sizeof(seed)) != 0) {
        fprintf(stderr, "DRNG initialization failed\n");
        return 2;
    }
    if (crypto_sign_keypair(pk, sk) != 0) {
        fprintf(stderr, "key generation failed\n");
        return 2;
    }
    if (write_file(pk_path, pk, sizeof(pk)) != 0) {
        fprintf(stderr, "public key write failed\n");
        return 2;
    }

    for (unsigned long long q = 1; q <= MAX_QUERIES; q++) {
        char msg[64];
        int n = snprintf(msg, sizeof(msg), "q:%llu", q);
        size_t siglen = 0;
        total_queries++;
        if (crypto_sign_signature(sig, &siglen, (const uint8_t *)msg,
                                  (size_t)n, sk) != 0 ||
            siglen != SPX_BYTES) {
            fprintf(stderr, "signing failed at query %llu\n", q);
            return 3;
        }

        {
            spx_ctx ctx = {0};
            memcpy(ctx.pub_seed, pk, SPX_N);
            uint64_t tree = UINT64_MAX;
            uint32_t leaf = UINT32_MAX;
            uint32_t counter = (uint32_t)digest_bytes_to_ull(
                sig + SPX_N, 4);
            if (hash_message(digest, &tree, &leaf, sig, pk,
                             (const unsigned char *)msg, (size_t)n,
                             &ctx, &counter) != 0) {
                fprintf(stderr, "digest replay failed at query %llu\n", q);
                return 3;
            }
            if (tree == 0 && leaf == 0) {
                same_instance++;
                if (retained < MAX_RETAINED) {
                    memcpy(records + retained * SPX_BYTES, sig, SPX_BYTES);
                    digest_indices(indices, digest);
                    for (unsigned int i = 0; i < SPX_FORS_TREES; i++) {
                        unsigned int idx = indices[i];
                        if (representative[i][idx] < 0) {
                            representative[i][idx] = (int)retained;
                            covered_positions[i]++;
                            covered++;
                        }
                    }
                    retained++;
                }
            }
        }
    }

    /*
     * Find a fresh message and attacker-chosen R for which the implementation's
     * public digest/XOF routine accepts some counter, selects (tree,leaf)=(0,0),
     * and selects only FORS positions present in the retained records.
     */
    {
        const char fresh[] = "forged-optimized-message01";
        uint64_t state = UINT64_C(0x4345445255532b43);
        for (unsigned long long trial = 1; trial <= 1000000ULL; trial++) {
            unsigned char R[SPX_N];
            for (unsigned int i = 0; i < SPX_N; i += 8) {
                uint64_t word = splitmix64(&state);
                size_t take = SPX_N - i < 8 ? SPX_N - i : 8;
                memcpy(R + i, &word, take);
            }
            memcpy(forged, R, SPX_N);
            attack_counter = 0;
            {
                spx_ctx ctx = {0};
                memcpy(ctx.pub_seed, pk, SPX_N);
                if (hash_message(digest, &attack_tree, &attack_leaf, forged,
                                 pk, (const unsigned char *)fresh,
                                 sizeof(fresh) - 1, &ctx,
                                 &attack_counter) != 0) {
                    continue;
                }
            }
            attack_trials = trial;
            if (attack_leaf != 0) {
                continue;
            }
            digest_indices(indices, digest);
            int available = 1;
            for (unsigned int i = 0; i < SPX_FORS_TREES; i++) {
                if (representative[i][indices[i]] < 0) {
                    available = 0;
                    break;
                }
            }
            if (available) {
                break;
            }
        }
        if (attack_leaf != 0 || attack_trials == 0) {
            fprintf(stderr, "fresh-message digest search failed\n");
            return 4;
        }
        for (unsigned int i = 0; i < SPX_FORS_TREES; i++) {
            if (representative[i][indices[i]] < 0) {
                fprintf(stderr, "fresh-message digest search exhausted\n");
                return 4;
            }
        }
        {
            unsigned char ctr[4];
            for (int i = 3; i >= 0; i--) {
                ctr[i] = (unsigned char)(attack_counter & 0xff);
                attack_counter >>= 8;
            }
            memcpy(forged + SPX_N, ctr, 4);
        }
        for (unsigned int i = 0; i < SPX_FORS_TREES; i++) {
            const unsigned char *group =
                records + (size_t)representative[i][indices[i]] * SPX_BYTES +
                SPX_N + 4 + i * (SPX_FORS_HEIGHT + 1) * SPX_N;
            memcpy(forged + SPX_N + 4 + i * (SPX_FORS_HEIGHT + 1) * SPX_N,
                   group, (SPX_FORS_HEIGHT + 1) * SPX_N);
        }
        memcpy(forged + SPX_N + 4 + SPX_FORS_BYTES,
               records + SPX_N + 4 + SPX_FORS_BYTES,
               SPX_BYTES - SPX_N - 4 - SPX_FORS_BYTES);

        valid_positive_control =
            crypto_sign_verify(records, SPX_BYTES,
                               (const uint8_t *)"q:1", 3, pk) == 0;
        if (write_file(forged_path, forged, SPX_BYTES) != 0) {
            fprintf(stderr, "forged signature write failed\n");
            return 5;
        }

        int forged_verify_rc =
            crypto_sign_verify(forged, SPX_BYTES,
                               (const uint8_t *)fresh, sizeof(fresh) - 1, pk);
        unsigned char mutated_sig[SPX_BYTES];
        unsigned char mutated_msg[sizeof(fresh)];
        memcpy(mutated_sig, forged, SPX_BYTES);
        mutated_sig[SPX_BYTES - 1] ^= 1;
        int mutated_signature_rc =
            crypto_sign_verify(mutated_sig, SPX_BYTES,
                               (const uint8_t *)fresh, sizeof(fresh) - 1, pk);
        memcpy(mutated_msg, fresh, sizeof(fresh));
        mutated_msg[0] ^= 1;
        int mutated_message_rc =
            crypto_sign_verify(forged, SPX_BYTES, mutated_msg,
                               sizeof(fresh) - 1, pk);

        FILE *f = fopen(report_path, "w");
        if (f == NULL) {
            return 5;
        }
        fprintf(f,
                "{\n"
                "  \"implementation\": \"Optimized_Implementation/CEDRUSC-160f\",\n"
                "  \"parameter_set\": \"CEDRUS+C-160f\",\n"
                "  \"queries\": %llu,\n"
                "  \"same_instance_tree0_leaf0\": %llu,\n"
                "  \"retained_records\": %llu,\n"
                "  \"fors_bit_capacity\": %u,\n"
                "  \"fors_bits_covered\": %llu,\n"
                "  \"fors_bit_fraction\": %.12f,\n"
                "  \"digest_search_trials\": %llu,\n"
                "  \"forge_fors_counter\": %u,\n"
                "  \"forged_message\": \"%s\",\n"
                "  \"base_retained_verify_rc\": %d,\n"
                "  \"forged_verify_rc\": %d,\n"
                "  \"signature_mutation_verify_rc\": %d,\n"
                "  \"message_mutation_verify_rc\": %d,\n"
                "  \"signature_bytes\": %d,\n"
                "  \"public_key_bytes\": %d,\n"
                "  \"secret_key_bytes\": %d\n"
                "}\n",
                total_queries, same_instance, retained,
                SPX_FORS_TREES * (1U << SPX_FORS_HEIGHT), covered,
                (double)covered /
                    (double)(SPX_FORS_TREES * (1U << SPX_FORS_HEIGHT)),
                attack_trials, (uint32_t)digest_bytes_to_ull(forged + SPX_N, 4),
                fresh,
                valid_positive_control ? 0 : -1,
                forged_verify_rc, mutated_signature_rc, mutated_message_rc,
                SPX_BYTES, SPX_PK_BYTES, SPX_SK_BYTES);
        fclose(f);
        printf("queries=%llu same_instance=%llu retained=%llu covered=%llu/%u "
               "trials=%llu forged_rc=%d sig_mut_rc=%d msg_mut_rc=%d "
               "base_rc=%d\n",
               total_queries, same_instance, retained, covered,
               SPX_FORS_TREES * (1U << SPX_FORS_HEIGHT), attack_trials,
               forged_verify_rc, mutated_signature_rc, mutated_message_rc,
               valid_positive_control ? 0 : -1);
    }

    free(forged);
    free(sig);
    free(records);
    return 0;
}
