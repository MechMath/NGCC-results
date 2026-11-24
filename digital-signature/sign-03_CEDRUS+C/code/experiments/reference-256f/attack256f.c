#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <time.h>

#include "api.h"
#include "auxfunc.h"
#include "counters.h"
#include "drng.h"
#include "hash.h"
#include "utils.h"

#define FORS_BLOCK_BYTES ((SPX_FORS_HEIGHT + 1) * SPX_N)
#define FORS_BYTES ((SPX_FORS_HEIGHT + 1) * SPX_FORS_TREES * SPX_N)
#define SIG_FORS_OFF (SPX_N + COUNTER_SIZE)
#define SIG_SUFFIX_OFF (SIG_FORS_OFF + FORS_BYTES)
#define SIG_SUFFIX_BYTES (CRYPTO_BYTES - SIG_SUFFIX_OFF)
#define TARGET_SIGNATURES 600
#define MAX_QUERIES 10000
#define MAX_DIGEST_CANDIDATES 1000000000ULL

DRNG_ctx drng_algorithm;

static double now_seconds(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        perror("clock_gettime");
        exit(2);
    }
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static void die(const char *msg) {
    fprintf(stderr, "fatal: %s: %s\n", msg, strerror(errno));
    exit(2);
}

static void message_to_indices(unsigned int indices[SPX_FORS_TREES],
                               const unsigned char digest[SPX_FORS_MSG_BYTES]) {
    unsigned int offset = 0;
    for (unsigned int i = 0; i < SPX_FORS_TREES; i++) {
        indices[i] = 0;
        for (unsigned int j = 0; j < SPX_FORS_HEIGHT; j++) {
            indices[i] ^= ((digest[offset >> 3] >> (offset & 7)) & 1U) << j;
            offset++;
        }
    }
}

static int parse_digest(unsigned char digest[SPX_FORS_MSG_BYTES],
                        uint64_t *tree, uint32_t *leaf,
                        const unsigned char *R, const unsigned char *pk,
                        const unsigned char *m, size_t mlen,
                        const spx_ctx *ctx, uint32_t counter) {
    uint32_t c = counter;
    return hash_message(digest, tree, leaf, R, pk, m, mlen, ctx, &c);
}

static void write_file(const char *path, const unsigned char *data, size_t len) {
    FILE *f = fopen(path, "wb");
    if (!f) die(path);
    if (len && fwrite(data, 1, len, f) != len) die("short write");
    if (fclose(f) != 0) die("close");
}

int main(void) {
    const double wall_start = now_seconds();
    unsigned char seed[CRYPTO_SEEDBYTES];
    unsigned char pk[CRYPTO_PUBLICKEYBYTES];
    unsigned char sk[CRYPTO_SECRETKEYBYTES];
    unsigned char *sig = malloc(CRYPTO_BYTES);
    if (!sig) die("signature allocation");

    for (size_t i = 0; i < sizeof(seed); i++) seed[i] = (unsigned char)(0x40 + (i * 17) % 191);
    if (init_random_number(&drng_algorithm, seed, sizeof(seed)) != 0) {
        fprintf(stderr, "fatal: DRNG init failed\n");
        return 2;
    }
    const double key_start = now_seconds();
    if (crypto_sign_seed_keypair(pk, sk, seed) != 0) {
        fprintf(stderr, "fatal: keygen failed\n");
        return 2;
    }
    const double key_elapsed = now_seconds() - key_start;

    spx_ctx ctx;
    memset(&ctx, 0, sizeof(ctx));
    memcpy(ctx.pub_seed, pk, SPX_N);
    initialize_hash_function(&ctx);

    /*
     * FORS block for tree i and selected index x occupies 288 bytes:
     * one 32-byte secret-key component followed by an 8-node path.
     */
    unsigned char *fors = calloc((size_t)SPX_FORS_TREES * 256 * FORS_BLOCK_BYTES, 1);
    unsigned char *covered = calloc((size_t)SPX_FORS_TREES * 256, 1);
    unsigned int *cover_count = calloc(SPX_FORS_TREES, sizeof(unsigned int));
    unsigned int *first_record = malloc((size_t)SPX_FORS_TREES * 256 * sizeof(unsigned int));
    if (!fors || !covered || !cover_count || !first_record) die("coverage allocation");
    for (size_t i = 0; i < (size_t)SPX_FORS_TREES * 256; i++) first_record[i] = UINT32_MAX;

    unsigned char suffix[SIG_SUFFIX_BYTES];
    int have_suffix = 0;
    uint32_t target_leaf = UINT32_MAX;
    unsigned int target_records = 0;
    unsigned int valid_signing_calls = 0;
    unsigned int failed_signing_calls = 0;
    unsigned int verifier_checks = 0;
    unsigned int verifier_failures = 0;

    FILE *qlog = fopen("experiments/query-log.tsv", "wb");
    FILE *rlog = fopen("experiments/retained-records.tsv", "wb");
    FILE *flog = fopen("experiments/fors-coverage.tsv", "wb");
    if (!qlog || !rlog || !flog) die("log open");
    fprintf(qlog, "query\tmessage\tsign_rc\tsiglen\tvalid_verify\n");
    fprintf(rlog, "retained_record\tquery\tmessage\teffective_leaf\n");
    fprintf(flog, "tree\tselected_index\tmessage\n");

    unsigned int queries = 0;
    while (target_records < TARGET_SIGNATURES && queries < MAX_QUERIES) {
        char msg[128];
        int n = snprintf(msg, sizeof(msg), "ordinary-query-256f-%06u", queries);
        if (n <= 0 || (size_t)n >= sizeof(msg)) return 2;
        size_t siglen = 0;
        int rc = crypto_sign_signature(sig, &siglen, (const unsigned char *)msg,
                                       (size_t)n, sk);
        if (rc != 0 || siglen != CRYPTO_BYTES) {
            failed_signing_calls++;
            fprintf(qlog, "%u\t%s\t%d\t%zu\t0\n", queries, msg, rc, siglen);
            queries++;
            continue;
        }
        valid_signing_calls++;

        uint32_t counter = get_fors_counter(sig);
        unsigned char digest[SPX_FORS_MSG_BYTES];
        uint64_t tree;
        uint32_t leaf;
        int hrc = parse_digest(digest, &tree, &leaf, sig, pk,
                               (const unsigned char *)msg, (size_t)n, &ctx, counter);
        int vrc = crypto_sign_verify(sig, siglen, (const unsigned char *)msg,
                                     (size_t)n, pk);
        verifier_checks++;
        if (vrc != 0) verifier_failures++;
        fprintf(qlog, "%u\t%s\t%d\t%zu\t%d\n", queries, msg, rc, siglen, vrc == 0);

        if (hrc == 0 && vrc == 0 && tree == 0) {
            if (target_leaf == UINT32_MAX) target_leaf = leaf;
            if (leaf == target_leaf) {
                unsigned int indices[SPX_FORS_TREES];
                message_to_indices(indices, digest);
                for (unsigned int i = 0; i < SPX_FORS_TREES; i++) {
                    size_t pos = (size_t)i * 256 + indices[i];
                    const unsigned char *block = sig + SIG_FORS_OFF +
                                                 (size_t)i * FORS_BLOCK_BYTES;
                    if (!covered[pos]) {
                        memcpy(fors + pos * FORS_BLOCK_BYTES, block, FORS_BLOCK_BYTES);
                        covered[pos] = 1;
                        cover_count[i]++;
                        first_record[pos] = target_records;
                        fprintf(flog, "%u\t%u\t%s\n", i, indices[i], msg);
                    }
                }
                if (!have_suffix) {
                    memcpy(suffix, sig + SIG_SUFFIX_OFF, SIG_SUFFIX_BYTES);
                    have_suffix = 1;
                }
                fprintf(rlog, "%u\t%u\t%s\t%u\n", target_records, queries, msg, leaf);
                target_records++;
            }
        }
        queries++;
        if ((queries % 100) == 0) {
            double c = 1.0;
            for (unsigned int i = 0; i < SPX_FORS_TREES; i++) c *= (double)cover_count[i] / 256.0;
            fprintf(stderr, "queries=%u target_records=%u leaf=%" PRIu32
                    " coverage_product=%.12g elapsed=%.3fs\n",
                    queries, target_records, target_leaf, c, now_seconds() - wall_start);
        }
    }
    fclose(qlog);
    fclose(rlog);
    fclose(flog);

    if (target_records < TARGET_SIGNATURES || !have_suffix) {
        fprintf(stderr, "insufficient target records: %u after %u queries\n",
                target_records, queries);
        return 3;
    }

    double coverage_product = 1.0;
    for (unsigned int i = 0; i < SPX_FORS_TREES; i++)
        coverage_product *= (double)cover_count[i] / 256.0;

    const char *fresh_msg = "256f-fresh-unqueried-message-20261113";
    const size_t fresh_len = strlen(fresh_msg);
    for (unsigned int i = 0; i < queries; i++) {
        char old[128];
        int n = snprintf(old, sizeof(old), "ordinary-query-256f-%06u", i);
        if (n == (int)fresh_len && memcmp(old, fresh_msg, fresh_len) == 0) {
            fprintf(stderr, "fatal: target message occurred in query set\n");
            return 4;
        }
    }

    unsigned char *candidate = malloc(CRYPTO_BYTES);
    if (!candidate) die("candidate allocation");
    uint64_t searched = 0;
    uint64_t pruned = 0;
    uint64_t wrong_leaf = 0;
    uint64_t uncovered = 0;
    uint32_t winning_counter = 0;
    unsigned char winning_R[SPX_N];
    unsigned int winning_indices[SPX_FORS_TREES];
    int found = 0;
    const double search_start = now_seconds();

    while (searched < MAX_DIGEST_CANDIDATES) {
        uint64_t variant = searched >> 10;
        uint32_t counter = (uint32_t)(searched & 1023ULL) + 1;
        unsigned char seedbuf[16];
        for (unsigned int i = 0; i < 8; i++) seedbuf[i] = (unsigned char)(variant >> (8 * i));
        for (unsigned int i = 8; i < 16; i++) seedbuf[i] = (unsigned char)(0xa5u ^ (i * 29u));
        unsigned char R[SPX_N];
        if (pseudoXOF((unsigned long long)SPX_N * 8, seedbuf,
                      (unsigned long long)sizeof(seedbuf) * 8, R) != 0) {
            fprintf(stderr, "fatal: candidate R generation failed\n");
            return 2;
        }
        unsigned char digest[SPX_FORS_MSG_BYTES];
        uint64_t tree;
        uint32_t leaf;
        int hrc = parse_digest(digest, &tree, &leaf, R, pk,
                               (const unsigned char *)fresh_msg, fresh_len, &ctx, counter);
        searched++;
        if (hrc != 0) {
            pruned++;
            continue;
        }
        if (leaf != target_leaf) {
            wrong_leaf++;
            continue;
        }
        unsigned int indices[SPX_FORS_TREES];
        message_to_indices(indices, digest);
        int all = 1;
        for (unsigned int i = 0; i < SPX_FORS_TREES; i++) {
            if (!covered[(size_t)i * 256 + indices[i]]) {
                all = 0;
                break;
            }
        }
        if (!all) {
            uncovered++;
            continue;
        }
        winning_counter = counter;
        memcpy(winning_R, R, SPX_N);
        memcpy(winning_indices, indices, sizeof(indices));
        found = 1;
        break;
    }
    const double search_elapsed = now_seconds() - search_start;
    if (!found) {
        fprintf(stderr, "no covered digest after %" PRIu64 " candidates\n", searched);
        return 5;
    }

    memcpy(candidate, winning_R, SPX_N);
    ull_to_bytes(candidate + SPX_N, COUNTER_SIZE, winning_counter);
    for (unsigned int i = 0; i < SPX_FORS_TREES; i++) {
        size_t pos = (size_t)i * 256 + winning_indices[i];
        memcpy(candidate + SIG_FORS_OFF + (size_t)i * FORS_BLOCK_BYTES,
               fors + pos * FORS_BLOCK_BYTES, FORS_BLOCK_BYTES);
    }
    memcpy(candidate + SIG_SUFFIX_OFF, suffix, SIG_SUFFIX_BYTES);

    int forged_rc = crypto_sign_verify(candidate, CRYPTO_BYTES,
                                       (const unsigned char *)fresh_msg,
                                       fresh_len, pk);
    unsigned char sig_mut[CRYPTO_BYTES];
    memcpy(sig_mut, candidate, CRYPTO_BYTES);
    sig_mut[SIG_FORS_OFF + 17] ^= 1;
    int sig_mut_rc = crypto_sign_verify(sig_mut, CRYPTO_BYTES,
                                        (const unsigned char *)fresh_msg,
                                        fresh_len, pk);
    unsigned char msg_mut[256];
    memcpy(msg_mut, fresh_msg, fresh_len);
    msg_mut[0] ^= 1;
    int msg_mut_rc = crypto_sign_verify(candidate, CRYPTO_BYTES,
                                        msg_mut, fresh_len, pk);

    write_file("experiments/public-key.bin", pk, CRYPTO_PUBLICKEYBYTES);
    write_file("experiments/forged-message.bin",
               (const unsigned char *)fresh_msg, fresh_len);
    write_file("experiments/forged-signature.bin", candidate, CRYPTO_BYTES);
    write_file("experiments/target-suffix.bin", suffix, SIG_SUFFIX_BYTES);

    struct rusage ru;
    getrusage(RUSAGE_SELF, &ru);
    const double wall = now_seconds() - wall_start;
    FILE *summary = fopen("experiments/attack-summary.txt", "wb");
    if (!summary) die("summary");
    fprintf(summary, "implementation=Reference_Implementation/CEDRUSC-256f\n");
    fprintf(summary, "parameters=n=%d,h=%d,d=%d,a=%d,k=%d,a_prime=%d,effective_T=4\n",
            SPX_N, SPX_FULL_HEIGHT, SPX_D, SPX_FORS_HEIGHT, SPX_FORS_TREES,
            SPX_FORS_ZERO_LAST_BITS);
    fprintf(summary, "signature_bytes=%d\n", CRYPTO_BYTES);
    fprintf(summary, "public_key_bytes=%d\n", CRYPTO_PUBLICKEYBYTES);
    fprintf(summary, "target_leaf=%" PRIu32 "\n", target_leaf);
    fprintf(summary, "queries=%u\n", queries);
    fprintf(summary, "valid_signing_calls=%u\n", valid_signing_calls);
    fprintf(summary, "failed_signing_calls=%u\n", failed_signing_calls);
    fprintf(summary, "query_verify_checks=%u\n", verifier_checks);
    fprintf(summary, "query_verify_failures=%u\n", verifier_failures);
    fprintf(summary, "retained_target_instance_records=%u\n", target_records);
    fprintf(summary, "coverage_product=%.17g\n", coverage_product);
    for (unsigned int i = 0; i < SPX_FORS_TREES; i++)
        fprintf(summary, "coverage_tree_%u=%u/256\n", i, cover_count[i]);
    fprintf(summary, "digest_candidates_searched=%" PRIu64 "\n", searched);
    fprintf(summary, "digest_candidates_pruned=%" PRIu64 "\n", pruned);
    fprintf(summary, "digest_candidates_wrong_leaf=%" PRIu64 "\n", wrong_leaf);
    fprintf(summary, "digest_candidates_uncovered=%" PRIu64 "\n", uncovered);
    fprintf(summary, "winning_fors_counter=%" PRIu32 "\n", winning_counter);
    fprintf(summary, "fresh_message=%s\n", fresh_msg);
    fprintf(summary, "fresh_message_length=%zu\n", fresh_len);
    for (unsigned int i = 0; i < SPX_FORS_TREES; i++)
        fprintf(summary, "winning_index_%u=%u\n", i, winning_indices[i]);
    fprintf(summary, "forged_verify_rc=%d\n", forged_rc);
    fprintf(summary, "signature_mutation_verify_rc=%d\n", sig_mut_rc);
    fprintf(summary, "message_mutation_verify_rc=%d\n", msg_mut_rc);
    fprintf(summary, "keygen_seconds=%.9f\n", key_elapsed);
    fprintf(summary, "digest_search_seconds=%.9f\n", search_elapsed);
    fprintf(summary, "wall_seconds=%.9f\n", wall);
    fprintf(summary, "user_seconds=%.9f\n",
            (double)ru.ru_utime.tv_sec + (double)ru.ru_utime.tv_usec / 1e6);
    fprintf(summary, "system_seconds=%.9f\n",
            (double)ru.ru_stime.tv_sec + (double)ru.ru_stime.tv_usec / 1e6);
    fprintf(summary, "maxrss_kib=%ld\n", ru.ru_maxrss);
    fprintf(summary, "coverage_storage_bytes=%zu\n",
            (size_t)SPX_FORS_TREES * 256 * FORS_BLOCK_BYTES);
    fclose(summary);

    fprintf(stdout, "target_leaf=%" PRIu32 " queries=%u records=%u candidates=%" PRIu64
            " forged_verify_rc=%d sig_mut_rc=%d msg_mut_rc=%d wall=%.3fs\n",
            target_leaf, queries, target_records, searched,
            forged_rc, sig_mut_rc, msg_mut_rc, wall);
    free(candidate);
    free(first_record);
    free(cover_count);
    free(covered);
    free(fors);
    free(sig);
    return forged_rc == 0 && sig_mut_rc != 0 && msg_mut_rc != 0 ? 0 : 6;
}
