#include <dirent.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <time.h>

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
#define EFFECTIVE_LEAF_BITS ((SPX_FULL_HEIGHT / SPX_D) - 1)

struct record_file {
    char path[1024];
    unsigned int count;
};

static void message_indices(uint32_t indices[SPX_FORS_TREES],
                            const unsigned char *m)
{
    unsigned int offset = 0;
    for (unsigned int i = 0; i < SPX_FORS_TREES; i++) {
        indices[i] = 0;
        for (unsigned int j = 0; j < SPX_FORS_HEIGHT; j++) {
            indices[i] ^=
                ((m[offset >> 3] >> (offset & 7)) & 1u) << j;
            offset++;
        }
    }
}

static int compare_files(const void *a, const void *b)
{
    const struct record_file *fa = a;
    const struct record_file *fb = b;
    return strcmp(fa->path, fb->path);
}

static int read_record(FILE *f, unsigned char *msg, unsigned char *sig)
{
    return fread(msg, 1, MESSAGE_BYTES, f) == MESSAGE_BYTES &&
           fread(sig, 1, SPX_BYTES, f) == SPX_BYTES;
}

int main(int argc, char **argv)
{
    struct timespec started, finished;
    struct rusage usage;
    clock_gettime(CLOCK_MONOTONIC, &started);
    const char *directory = argc > 1 ? argv[1] : "experiments/oracle-records";
    const unsigned int desired = argc > 2 ? strtoul(argv[2], NULL, 0) : 400;
    const uint32_t target_leaf = 0;
    unsigned char expected_pk[SPX_PK_BYTES];
    unsigned char final_msg[MESSAGE_BYTES] = {
        0x66, 0x6f, 0x72, 0x67, 0x65, 0x64, 0x2d, 0x6d,
        0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x30, 0x31
    };
    unsigned char *record_msg = calloc(MAX_RECORDS, MESSAGE_BYTES);
    unsigned char *record_sig = calloc((size_t)MAX_RECORDS, SPX_BYTES);
    unsigned int *source_by_index =
        calloc((size_t)SPX_FORS_TREES << SPX_FORS_HEIGHT, sizeof(unsigned int));
    unsigned int *record_indices =
        calloc((size_t)MAX_RECORDS * SPX_FORS_TREES, sizeof(unsigned int));
    unsigned char *final_sig = calloc(SPX_BYTES, 1);
    unsigned char mhash[SPX_FORS_MSG_BYTES];
    unsigned char pk[SPX_PK_BYTES];
    unsigned char r[SPX_N];
    spx_ctx ctx = {0};
    struct record_file files[256];
    unsigned int file_count = 0;
    unsigned int record_count = 0;
    int have_pk = 0;

    DIR *dir = opendir(directory);
    if (!dir) {
        perror(directory);
        return 2;
    }
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strncmp(entry->d_name, "oracle-", 7) != 0 ||
            strstr(entry->d_name, ".bin") == NULL) {
            continue;
        }
        if (file_count == sizeof(files) / sizeof(files[0])) {
            return 3;
        }
        snprintf(files[file_count].path, sizeof(files[file_count].path),
                 "%s/%s", directory, entry->d_name);
        file_count++;
    }
    closedir(dir);
    qsort(files, file_count, sizeof(files[0]), compare_files);

    for (unsigned int n = 0; n < file_count && record_count < MAX_RECORDS; n++) {
        FILE *f = fopen(files[n].path, "rb");
        if (!f) {
            return 4;
        }
        unsigned char file_pk[SPX_PK_BYTES];
        if (fread(file_pk, 1, SPX_PK_BYTES, f) != SPX_PK_BYTES) {
            fclose(f);
            return 5;
        }
        if (!have_pk) {
            memcpy(pk, file_pk, sizeof(pk));
            have_pk = 1;
        } else if (memcmp(pk, file_pk, sizeof(pk)) != 0) {
            fprintf(stderr, "public-key mismatch in %s\n", files[n].path);
            return 6;
        }
        while (record_count < MAX_RECORDS &&
               read_record(f, record_msg + (size_t)record_count * MESSAGE_BYTES,
                           record_sig + (size_t)record_count * SPX_BYTES)) {
            record_count++;
        }
        fclose(f);
    }
    if (!have_pk || record_count < desired) {
        fprintf(stderr, "need %u records, found %u\n", desired, record_count);
        return 7;
    }

    memset(ctx.pub_seed, 0, SPX_N);
    memcpy(ctx.pub_seed, pk, SPX_N);
    initialize_hash_function(&ctx);

    for (unsigned int j = 0; j < desired; j++) {
        const unsigned char *sig = record_sig + (size_t)j * SPX_BYTES;
        const unsigned char *msg =
            record_msg + (size_t)j * MESSAGE_BYTES;
        uint32_t counter = get_fors_counter(sig);
        uint64_t tree;
        uint32_t leaf;
        if (hash_message(mhash, &tree, &leaf, sig, pk, msg,
                         MESSAGE_BYTES, &ctx, &counter) != 0 ||
            leaf != target_leaf) {
            fprintf(stderr, "record %u is not on target leaf\n", j);
            return 8;
        }
        message_indices(record_indices + (size_t)j * SPX_FORS_TREES, mhash);
        for (unsigned int i = 0; i < SPX_FORS_TREES; i++) {
            uint32_t idx = record_indices[(size_t)j * SPX_FORS_TREES + i];
            source_by_index[((size_t)i << SPX_FORS_HEIGHT) + idx] = j + 1;
        }
    }

    unsigned int covered_positions = 0;
    double conditional_success = 1.0;
    const double bucket_size = (double)(1u << SPX_FORS_HEIGHT);
    for (unsigned int i = 0; i < SPX_FORS_TREES; i++) {
        unsigned int seen = 0;
        for (unsigned int x = 0; x < (1u << SPX_FORS_HEIGHT); x++) {
            if (source_by_index[((size_t)i << SPX_FORS_HEIGHT) + x]) {
                seen++;
            }
        }
        covered_positions += seen;
        conditional_success *= seen / bucket_size;
    }
    const double target_probability =
        conditional_success / (double)(1u << SPX_FORS_ZERO_LAST_BITS) /
        (double)(1u << EFFECTIVE_LEAF_BITS);
    printf("records=%u covered_positions=%u conditional_coverage=%.17g "
           "target_probability=%.17g expected_trials=%.6f\n",
           desired, covered_positions, conditional_success, target_probability,
           1.0 / target_probability);

    uint32_t found_counter = 0;
    uint64_t found_trial = 0;
    int found = 0;
    for (uint64_t trial = 1; trial <= (1ull << 32); trial++) {
        uint64_t x = trial;
        memset(r, 0, sizeof(r));
        memcpy(r, &x, sizeof(x));
        uint32_t counter = 0;
        uint64_t tree;
        uint32_t leaf;
        if (hash_message(mhash, &tree, &leaf, r, pk, final_msg,
                         MESSAGE_BYTES, &ctx, &counter) != 0 ||
            leaf != target_leaf) {
            continue;
        }
        message_indices(record_indices, mhash);
        int covered = 1;
        for (unsigned int i = 0; i < SPX_FORS_TREES; i++) {
            if (!source_by_index[((size_t)i << SPX_FORS_HEIGHT) +
                                 record_indices[i]]) {
                covered = 0;
                break;
            }
        }
        if (covered) {
            found_counter = counter;
            found_trial = trial;
            found = 1;
            break;
        }
    }
    if (!found) {
        fprintf(stderr, "no forged digest within 2^32 trials\n");
        return 9;
    }

    memcpy(final_sig, r, SPX_N);
    ull_to_bytes(final_sig + SPX_N, COUNTER_SIZE, found_counter);
    size_t fors_header = SPX_N + COUNTER_SIZE;
    size_t subtree_bytes = (SPX_FORS_HEIGHT + 1) * SPX_N;
    for (unsigned int i = 0; i < SPX_FORS_TREES; i++) {
        uint32_t idx = record_indices[i];
        unsigned int source = source_by_index[
            ((size_t)i << SPX_FORS_HEIGHT) + idx] - 1;
        memcpy(final_sig + fors_header + (size_t)i * subtree_bytes,
               record_sig + (size_t)source * SPX_BYTES + fors_header +
                   (size_t)i * subtree_bytes,
               subtree_bytes);
    }
    size_t suffix_offset = fors_header + SPX_FORS_BYTES;
    memcpy(final_sig + suffix_offset, record_sig + suffix_offset,
           SPX_BYTES - suffix_offset);

    int verify_rc = sig_verify(pk, SPX_PK_BYTES, final_sig, SPX_BYTES,
                               final_msg, MESSAGE_BYTES);
    printf("forged_trial=%llu fors_counter=%u verify_rc=%d\n",
           (unsigned long long)found_trial, found_counter, verify_rc);
    if (verify_rc != 0) {
        return 10;
    }

    char sig_path[1200], msg_path[1200], summary_path[1200];
    snprintf(sig_path, sizeof(sig_path), "%s/forged-signature.bin", directory);
    snprintf(msg_path, sizeof(msg_path), "%s/forged-message.bin", directory);
    snprintf(summary_path, sizeof(summary_path), "%s/forge-summary.txt",
             directory);
    FILE *fo = fopen(sig_path, "wb");
    FILE *fm = fopen(msg_path, "wb");
    FILE *fs = fopen(summary_path, "w");
    if (!fo || !fm || !fs) {
        return 11;
    }
    fwrite(final_sig, 1, SPX_BYTES, fo);
    fwrite(final_msg, 1, MESSAGE_BYTES, fm);
    fprintf(fs,
            "records=%u covered_positions=%u conditional_coverage=%.17g\n"
            "target_probability=%.17g expected_trials=%.6f\n"
            "forged_trial=%llu fors_counter=%u verify_rc=%d\n",
            desired, covered_positions, conditional_success,
            target_probability, 1.0 / target_probability,
            (unsigned long long)found_trial, found_counter, verify_rc);
    clock_gettime(CLOCK_MONOTONIC, &finished);
    getrusage(RUSAGE_SELF, &usage);
    double elapsed = (double)(finished.tv_sec - started.tv_sec) +
                     (double)(finished.tv_nsec - started.tv_nsec) / 1e9;
    fprintf(fs, "forge_elapsed_seconds=%.6f max_rss_kb=%ld\n",
            elapsed, usage.ru_maxrss);
    printf("forge_elapsed_seconds=%.6f max_rss_kb=%ld\n",
           elapsed, usage.ru_maxrss);
    fclose(fs);
    fclose(fm);
    fclose(fo);
    free(record_indices);
    free(source_by_index);
    free(record_sig);
    free(record_msg);
    free(final_sig);
    return 0;
}
