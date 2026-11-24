#define _DEFAULT_SOURCE

#include <dirent.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "api.h"
#include "context.h"
#include "counters.h"
#include "hash.h"
#include "params.h"
#include "SIG_AlgorithmInstance.h"
#include "utils.h"

#define MESSAGE_BYTES 16
#define RECORD_BYTES (MESSAGE_BYTES + SPX_BYTES)
#define MAX_RECORDS 4096

struct audit_record {
    unsigned char message[MESSAGE_BYTES];
    unsigned char signature[SPX_BYTES];
    uint32_t fors_indices[SPX_FORS_TREES];
};

static int compare_names(const struct dirent **a, const struct dirent **b)
{
    return strcmp((*a)->d_name, (*b)->d_name);
}

static void digest_indices(uint32_t indices[SPX_FORS_TREES],
                           const unsigned char digest[SPX_FORS_MSG_BYTES])
{
    unsigned int bit = 0;
    for (unsigned int i = 0; i < SPX_FORS_TREES; i++) {
        indices[i] = 0;
        for (unsigned int j = 0; j < SPX_FORS_HEIGHT; j++, bit++) {
            indices[i] |=
                ((digest[bit >> 3] >> (bit & 7)) & 1u) << j;
        }
    }
}

static void query_message(unsigned int worker, unsigned int trial,
                          unsigned char message[MESSAGE_BYTES])
{
    uint64_t serial = ((uint64_t)worker << 32) | trial;
    memset(message, 0, MESSAGE_BYTES);
    memcpy(message, &serial, sizeof(serial));
    message[8] = (unsigned char)worker;
    message[9] = (unsigned char)(worker >> 8);
}

static int read_record(FILE *f, struct audit_record *record)
{
    size_t msg = fread(record->message, 1, MESSAGE_BYTES, f);
    if (msg == 0 && feof(f)) {
        return 0;
    }
    if (msg != MESSAGE_BYTES ||
        fread(record->signature, 1, SPX_BYTES, f) != SPX_BYTES) {
        fprintf(stderr, "truncated oracle record\n");
        exit(20);
    }
    return 1;
}

static int in_query_family(const unsigned char message[MESSAGE_BYTES])
{
    for (unsigned int worker = 0; worker < 16; worker++) {
        for (unsigned int trial = 0; trial < 150; trial++) {
            unsigned char query[MESSAGE_BYTES];
            query_message(worker, trial, query);
            if (memcmp(message, query, MESSAGE_BYTES) == 0) {
                return 1;
            }
        }
    }
    return 0;
}

static int read_file_exact(const char *path, unsigned char *out, size_t bytes)
{
    FILE *f = fopen(path, "rb");
    if (!f) {
        perror(path);
        return 0;
    }
    size_t got = fread(out, 1, bytes, f);
    unsigned char extra = 0;
    int has_extra = fread(&extra, 1, 1, f) != 0;
    fclose(f);
    return got == bytes && !has_extra;
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: %s ORACLE_DIRECTORY\n", argv[0]);
        return 2;
    }

    struct dirent **names = NULL;
    int name_count = scandir(argv[1], &names, NULL, compare_names);
    if (name_count < 0) {
        perror(argv[1]);
        return 3;
    }

    struct audit_record *records =
        calloc(MAX_RECORDS, sizeof(struct audit_record));
    unsigned char expected_pk[SPX_PK_BYTES];
    int have_pk = 0;
    unsigned int record_count = 0;
    unsigned int file_count = 0;
    unsigned int signature_pass = 0;

    spx_ctx ctx = {0};
    for (int n = 0; n < name_count; n++) {
        const char *name = names[n]->d_name;
        if (strncmp(name, "oracle-", 7) != 0 ||
            strstr(name, ".bin") == NULL) {
            free(names[n]);
            continue;
        }
        char path[4096];
        snprintf(path, sizeof(path), "%s/%s", argv[1], name);
        FILE *f = fopen(path, "rb");
        if (!f) {
            perror(path);
            return 4;
        }
        unsigned char pk[SPX_PK_BYTES];
        if (fread(pk, 1, sizeof(pk), f) != sizeof(pk)) {
            fprintf(stderr, "short public key: %s\n", path);
            return 5;
        }
        if (!have_pk) {
            memcpy(expected_pk, pk, sizeof(pk));
            have_pk = 1;
            memcpy(ctx.pub_seed, pk, SPX_N);
            initialize_hash_function(&ctx);
        } else if (memcmp(expected_pk, pk, sizeof(pk)) != 0) {
            fprintf(stderr, "public-key mismatch: %s\n", path);
            return 6;
        }
        file_count++;
        while (record_count < MAX_RECORDS && read_record(f, &records[record_count])) {
            record_count++;
        }
        unsigned char extra = 0;
        if (fread(&extra, 1, 1, f) != 0) {
            fprintf(stderr, "trailing/truncated bytes: %s\n", path);
            return 7;
        }
        fclose(f);
        free(names[n]);
    }
    free(names);

    for (unsigned int i = 0; i < record_count; i++) {
        struct audit_record *record = &records[i];
        if (sig_verify(expected_pk, sizeof(expected_pk),
                       record->signature, SPX_BYTES,
                       record->message, MESSAGE_BYTES) != 0) {
            fprintf(stderr, "ordinary verifier rejected record %u\n", i);
            return 8;
        }
        signature_pass++;

        unsigned char digest[SPX_FORS_MSG_BYTES];
        uint64_t tree = UINT64_MAX;
        uint32_t leaf = UINT32_MAX;
        uint32_t counter = get_fors_counter(record->signature);
        if (hash_message(digest, &tree, &leaf, record->signature,
                         expected_pk, record->message, MESSAGE_BYTES,
                         &ctx, &counter) != 0 ||
            tree != 0 || leaf != 0) {
            fprintf(stderr, "record %u not on tree=0 leaf=0\n", i);
            return 9;
        }
        digest_indices(record->fors_indices, digest);
        if (!in_query_family(record->message)) {
            fprintf(stderr, "record %u absent from deterministic query family\n", i);
            return 10;
        }
    }

    unsigned int seen_by_tree[SPX_FORS_TREES][1u << SPX_FORS_HEIGHT];
    memset(seen_by_tree, 0, sizeof(seen_by_tree));
    for (unsigned int i = 0; i < 400 && i < record_count; i++) {
        for (unsigned int t = 0; t < SPX_FORS_TREES; t++) {
            seen_by_tree[t][records[i].fors_indices[t]] = 1;
        }
    }
    unsigned int covered = 0;
    double conditional_coverage = 1.0;
    for (unsigned int t = 0; t < SPX_FORS_TREES; t++) {
        unsigned int seen = 0;
        for (unsigned int x = 0; x < (1u << SPX_FORS_HEIGHT); x++) {
            seen += seen_by_tree[t][x];
        }
        covered += seen;
        conditional_coverage *= (double)seen / (double)(1u << SPX_FORS_HEIGHT);
    }

    unsigned char forged_message[MESSAGE_BYTES];
    unsigned char forged_signature[SPX_BYTES];
    char path[4096];
    snprintf(path, sizeof(path), "%s/forged-message.bin", argv[1]);
    if (!read_file_exact(path, forged_message, sizeof(forged_message))) {
        return 11;
    }
    snprintf(path, sizeof(path), "%s/forged-signature.bin", argv[1]);
    if (!read_file_exact(path, forged_signature, sizeof(forged_signature))) {
        return 12;
    }

    int fresh = 1;
    for (unsigned int worker = 0; worker < 16; worker++) {
        for (unsigned int trial = 0; trial < 150; trial++) {
            unsigned char query[MESSAGE_BYTES];
            query_message(worker, trial, query);
            if (memcmp(forged_message, query, MESSAGE_BYTES) == 0) {
                fresh = 0;
            }
        }
    }
    int novel_signature = 1;
    for (unsigned int i = 0; i < record_count; i++) {
        if (memcmp(forged_signature, records[i].signature, SPX_BYTES) == 0) {
            novel_signature = 0;
        }
    }

    int forged_rc = sig_verify(expected_pk, sizeof(expected_pk),
                               forged_signature, sizeof(forged_signature),
                               forged_message, sizeof(forged_message));
    unsigned char tampered_signature[SPX_BYTES];
    unsigned char tampered_message[MESSAGE_BYTES];
    unsigned char tampered_pk[SPX_PK_BYTES];
    memcpy(tampered_signature, forged_signature, sizeof(tampered_signature));
    memcpy(tampered_message, forged_message, sizeof(tampered_message));
    memcpy(tampered_pk, expected_pk, sizeof(tampered_pk));
    tampered_signature[sizeof(tampered_signature) - 1] ^= 1;
    tampered_message[0] ^= 1;
    tampered_pk[0] ^= 1;
    int bad_signature_rc = sig_verify(expected_pk, sizeof(expected_pk),
                                      tampered_signature,
                                      sizeof(tampered_signature),
                                      forged_message,
                                      sizeof(forged_message));
    int bad_message_rc = sig_verify(expected_pk, sizeof(expected_pk),
                                    forged_signature,
                                    sizeof(forged_signature),
                                    tampered_message,
                                    sizeof(tampered_message));
    int bad_pk_rc = sig_verify(tampered_pk, sizeof(tampered_pk),
                               forged_signature, sizeof(forged_signature),
                               forged_message, sizeof(forged_message));

    printf("oracle_files=%u records=%u unique_public_key=%s "
           "ordinary_signatures_passed=%u tree_zero_leaf_zero=%u\n",
           file_count, record_count, have_pk ? "yes" : "no",
           signature_pass, signature_pass);
    printf("first_400_covered_positions=%u of %u "
           "conditional_coverage=%.17g\n",
           covered, SPX_FORS_TREES * (1u << SPX_FORS_HEIGHT),
           conditional_coverage);
    printf("forged_message_fresh_in_2400=%s forged_signature_novel=%s "
           "forged_message_bytes=%u forged_signature_bytes=%u\n",
           fresh ? "yes" : "no", novel_signature ? "yes" : "no",
           MESSAGE_BYTES, SPX_BYTES);
    printf("forged_verify_rc=%d bad_signature_rc=%d bad_message_rc=%d "
           "bad_public_key_rc=%d\n",
           forged_rc, bad_signature_rc, bad_message_rc, bad_pk_rc);

    free(records);
    return fresh && novel_signature && forged_rc == 0 &&
                   bad_signature_rc == -1 && bad_message_rc == -1 &&
                   bad_pk_rc == -1
               ? 0
               : 13;
}
