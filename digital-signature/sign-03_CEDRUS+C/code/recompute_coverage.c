#include <errno.h>
#include <glob.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "api.h"
#include "counters.h"
#include "hash.h"
#include "utils.h"

#define FORS_BLOCK ((SPX_FORS_HEIGHT + 1) * SPX_N)
#define FORS_OFF (SPX_N + COUNTER_SIZE)
#define FRESH_MESSAGE "256f-fresh-unqueried-message-20261113"

static void die(const char *what) {
    fprintf(stderr, "fatal: %s: %s\n", what, strerror(errno));
    exit(2);
}

static unsigned char *read_file(const char *path, size_t *n) {
    FILE *f = fopen(path, "rb");
    unsigned char *p;
    long end;

    if (f == NULL) die(path);
    if (fseek(f, 0, SEEK_END) != 0 || (end = ftell(f)) < 0 ||
        fseek(f, 0, SEEK_SET) != 0) die(path);
    *n = (size_t)end;
    p = malloc(*n == 0 ? 1 : *n);
    if (p == NULL || (*n != 0 && fread(p, 1, *n, f) != *n)) die(path);
    if (fclose(f) != 0) die(path);
    return p;
}

static void digest_indices(unsigned indices[SPX_FORS_TREES],
                           const unsigned char digest[SPX_FORS_MSG_BYTES]) {
    unsigned offset = 0;
    unsigned i;
    unsigned j;

    for (i = 0; i < SPX_FORS_TREES; i++) {
        indices[i] = 0;
        for (j = 0; j < SPX_FORS_HEIGHT; j++) {
            indices[i] ^= ((digest[offset >> 3] >> (offset & 7)) & 1U) << j;
            offset++;
        }
    }
}

static int digest_for_sig(unsigned indices[SPX_FORS_TREES], uint64_t *tree,
                          uint32_t *leaf, const unsigned char *sig,
                          const unsigned char *pk, const unsigned char *msg,
                          size_t mlen, const spx_ctx *ctx) {
    unsigned char digest[SPX_FORS_MSG_BYTES];
    uint32_t counter = get_fors_counter(sig);
    uint32_t c = counter;

    if (counter == 0) return -1;
    if (hash_message(digest, tree, leaf, sig, pk, msg, mlen, ctx, &c) != 0)
        return -1;
    if (indices != NULL) digest_indices(indices, digest);
    return 0;
}

int main(int argc, char **argv) {
    glob_t workers;
    char worker_pattern[4096];
    unsigned char common_pk[CRYPTO_PUBLICKEYBYTES];
    unsigned char *covered;
    unsigned *counts;
    unsigned char *seen_query;
    unsigned worker_count = 0;
    unsigned query_count = 0;
    unsigned retained_log_count = 0;
    unsigned record_count = 0;
    unsigned record_verify_failures = 0;
    size_t i;
    double coverage = 1.0;
    spx_ctx ctx;

    if (argc != 4) {
        fprintf(stderr, "usage: %s ORACLE_DIR FORGED_MESSAGE FORGED_SIGNATURE\n",
                argv[0]);
        return 2;
    }

    covered = calloc((size_t)SPX_FORS_TREES * 256, 1);
    counts = calloc(SPX_FORS_TREES, sizeof(*counts));
    seen_query = calloc(5440, 1);
    if (covered == NULL || counts == NULL || seen_query == NULL) die("allocation");

    if (snprintf(worker_pattern, sizeof(worker_pattern), "%s/*", argv[1]) >=
        (int)sizeof(worker_pattern)) die("path");
    if (glob(worker_pattern, GLOB_ONLYDIR, NULL, &workers) != 0) {
        fprintf(stderr, "no worker directories under %s\n", argv[1]);
        return 2;
    }

    for (i = 0; i < workers.gl_pathc; i++) {
        const char *worker = workers.gl_pathv[i];
        char path[4096];
        FILE *log;
        char line[1024];
        unsigned char *pk;
        size_t pkn;
        unsigned valid_lines = 0;
        char column[16];
        glob_t records;

        if (snprintf(path, sizeof(path), "%s/public-key.bin", worker) >=
            (int)sizeof(path)) die("path");
        pk = read_file(path, &pkn);
        if (pkn != CRYPTO_PUBLICKEYBYTES) {
            fprintf(stderr, "bad public key size in %s: %zu\n", worker, pkn);
            return 3;
        }
        if (worker_count == 0) {
            memcpy(common_pk, pk, sizeof(common_pk));
        } else if (memcmp(common_pk, pk, sizeof(common_pk)) != 0) {
            fprintf(stderr, "public key mismatch in %s\n", worker);
            return 3;
        }
        free(pk);
        worker_count++;

        if (snprintf(path, sizeof(path), "%s/query-log.tsv", worker) >=
            (int)sizeof(path)) die("path");
        log = fopen(path, "rb");
        if (log == NULL) die(path);
        if (fgets(line, sizeof(line), log) == NULL ||
            strcmp(line,
                   "query\tmessage\tsign_rc\tsiglen\tsha256_prefix\n") != 0) {
            fprintf(stderr, "bad query header in %s\n", path);
            return 3;
        }
        while (fgets(line, sizeof(line), log) != NULL) {
            unsigned q;
            char message[128];
            int sign_rc;
            size_t siglen;
            char expected[128];

            if (sscanf(line, "%u\t%127[^\t]\t%d\t%zu\t%15s",
                       &q, message, &sign_rc, &siglen, column) != 5) {
                fprintf(stderr, "bad query row in %s\n", path);
                return 3;
            }
            if (q >= 5440 || seen_query[q]) {
                fprintf(stderr, "duplicate/out-of-range query %u\n", q);
                return 3;
            }
            if (snprintf(expected, sizeof(expected), "ordinary-query-256f-%06u", q) >=
                (int)sizeof(expected) || strcmp(expected, message) != 0) {
                fprintf(stderr, "query/message mismatch %u\n", q);
                return 3;
            }
            if (sign_rc != 0 || siglen != CRYPTO_BYTES) {
                fprintf(stderr, "failed ordinary signing row %u\n", q);
                return 3;
            }
            if (strcmp(column, "retained") == 0) retained_log_count++;
            else if (strcmp(column, "other-instance") != 0) {
                fprintf(stderr, "unknown instance label %s\n", column);
                return 3;
            }
            seen_query[q] = 1;
            valid_lines++;
            query_count++;
        }
        if (fclose(log) != 0) die(path);
        if (valid_lines != 170) {
            fprintf(stderr, "worker %s has %u query rows, expected 170\n",
                    worker, valid_lines);
            return 3;
        }

        if (snprintf(path, sizeof(path), "%s/record-*.bin", worker) >=
            (int)sizeof(path)) die("path");
        if (glob(path, 0, NULL, &records) == 0) {
            size_t j;
            memset(&ctx, 0, sizeof(ctx));
            memcpy(ctx.pub_seed, common_pk, SPX_N);
            initialize_hash_function(&ctx);
            for (j = 0; j < records.gl_pathc; j++) {
                const char *record = records.gl_pathv[j];
                const char *base = strrchr(record, '/');
                unsigned q;
                char message[128];
                unsigned char *sig;
                size_t sn;
                uint64_t tree;
                uint32_t leaf;
                unsigned indices[SPX_FORS_TREES];
                unsigned t;

                base = base == NULL ? record : base + 1;
                if (sscanf(base, "record-%6u.bin", &q) != 1) {
                    fprintf(stderr, "bad record name %s\n", record);
                    return 3;
                }
                if (q >= 5440) return 3;
                if (snprintf(message, sizeof(message),
                             "ordinary-query-256f-%06u", q) >=
                    (int)sizeof(message)) return 3;
                sig = read_file(record, &sn);
                if (sn != CRYPTO_BYTES ||
                    crypto_sign_verify(sig, sn, (const unsigned char *)message,
                                       strlen(message), common_pk) != 0) {
                    record_verify_failures++;
                    free(sig);
                    continue;
                }
                if (digest_for_sig(indices, &tree, &leaf, sig, common_pk,
                                   (const unsigned char *)message,
                                   strlen(message), &ctx) != 0 ||
                    tree != 0 || leaf != 0) {
                    fprintf(stderr, "record %s does not select (tree,leaf)=(0,0)\n",
                            record);
                    return 4;
                }
                for (t = 0; t < SPX_FORS_TREES; t++) {
                    size_t position = (size_t)t * 256 + indices[t];
                    if (!covered[position]) {
                        covered[position] = 1;
                        counts[t]++;
                    }
                }
                record_count++;
                free(sig);
            }
            globfree(&records);
        }
    }
    globfree(&workers);

    if (worker_count != 32 || query_count != 5440 ||
        retained_log_count != 633 || record_count != 633 ||
        record_verify_failures != 0) {
        fprintf(stderr,
                "census mismatch workers=%u queries=%u retained_log=%u "
                "records=%u verify_failures=%u\n",
                worker_count, query_count, retained_log_count, record_count,
                record_verify_failures);
        return 4;
    }

    for (i = 0; i < SPX_FORS_TREES; i++)
        coverage *= (double)counts[i] / 256.0;

    {
        unsigned char *message;
        unsigned char *sig;
        size_t mlen;
        size_t sn;
        uint64_t tree;
        uint32_t leaf;
        unsigned indices[SPX_FORS_TREES];

        message = read_file(argv[2], &mlen);
        sig = read_file(argv[3], &sn);
        if (sn != CRYPTO_BYTES || mlen != strlen(FRESH_MESSAGE) ||
            memcmp(message, FRESH_MESSAGE, mlen) != 0) {
            fprintf(stderr, "fresh artifact size/content mismatch\n");
            return 5;
        }
        memset(&ctx, 0, sizeof(ctx));
        memcpy(ctx.pub_seed, common_pk, SPX_N);
        initialize_hash_function(&ctx);
        if (digest_for_sig(indices, &tree, &leaf, sig, common_pk, message,
                           mlen, &ctx) != 0 ||
            tree != 0 || leaf != 0) {
            fprintf(stderr, "fresh signature does not parse to (0,0)\n");
            return 5;
        }

        printf("workers=%u\n", worker_count);
        printf("queries=%u\n", query_count);
        printf("distinct_queries=%u\n", query_count);
        printf("ordinary_signing_successes=%u\n", query_count);
        printf("signature_length=%d\n", CRYPTO_BYTES);
        printf("shared_public_keys=1\n");
        printf("retained_log_rows=%u\n", retained_log_count);
        printf("retained_record_files=%u\n", record_count);
        printf("retained_record_verifications=%u\n", record_count);
        printf("retained_record_verify_failures=%u\n", record_verify_failures);
        printf("effective_instance_tree=%" PRIu64 "\n", tree);
        printf("effective_instance_leaf=%" PRIu32 "\n", leaf);
        printf("coverage_product=%.17g\n", coverage);
        for (i = 0; i < SPX_FORS_TREES; i++) {
            if (!covered[(size_t)i * 256 + indices[i]]) {
                fprintf(stderr, "fresh FORS index is uncovered at tree %zu\n", i);
                return 5;
            }
            printf("coverage_%zu=%u/256\n", i, counts[i]);
            printf("fresh_index_%zu=%u\n", i, indices[i]);
        }
        free(sig);
        free(message);
    }

    free(seen_query);
    free(counts);
    free(covered);
    return 0;
}
