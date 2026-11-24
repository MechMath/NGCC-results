#define _GNU_SOURCE

#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "api.h"
#include "context.h"
#include "counters.h"
#include "drng.h"
#include "hash.h"
#include "params.h"

#define WORKERS 32
#define QUERIES_PER_WORKER 170
#define HIT_MAGIC 0x36353246u
#define MAX_MESSAGE_BYTES 255u

DRNG_ctx drng_algorithm;

typedef struct {
    uint32_t magic;
    uint32_t worker;
    uint32_t query;
    uint32_t message_len;
    uint32_t forked_counter;
    uint32_t leaf;
    uint8_t message[MAX_MESSAGE_BYTES];
    uint8_t signature[SPX_BYTES];
} hit_record;

typedef struct {
    hit_record *items;
    size_t count;
    size_t capacity;
} hit_list;

static void die(const char *what)
{
    perror(what);
    exit(2);
}

static uint64_t splitmix64(uint64_t x)
{
    x += UINT64_C(0x9e3779b97f4a7c15);
    x = (x ^ (x >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
    x = (x ^ (x >> 27)) * UINT64_C(0x94d049bb133111eb);
    return x ^ (x >> 31);
}

static void derive_seed(uint8_t *seed, size_t seed_len, uint64_t domain,
                        uint64_t worker)
{
    for (size_t i = 0; i < seed_len; i++) {
        if ((i & 7) == 0) {
            uint64_t x = splitmix64(domain ^ (worker << 32) ^ (i >> 3));
            memcpy(seed + i, &x, seed_len - i < 8 ? seed_len - i : 8);
        }
    }
}

static void ensure_dir(const char *path)
{
    if (mkdir(path, 0755) != 0 && errno != EEXIST) {
        die(path);
    }
}

static void message_to_indices(uint32_t indices[SPX_FORS_TREES],
                               const uint8_t *m)
{
    unsigned int offset = 0;
    for (unsigned int i = 0; i < SPX_FORS_TREES; i++) {
        indices[i] = 0;
        for (unsigned int j = 0; j < SPX_FORS_HEIGHT; j++) {
            indices[i] ^= ((m[offset >> 3] >> (offset & 7)) & 1u) << j;
            offset++;
        }
    }
}

static int parse_signature(uint64_t *tree, uint32_t *leaf, uint8_t digest[SPX_FORS_MSG_BYTES],
                           const uint8_t *signature, const uint8_t *message,
                           size_t message_len, const uint8_t *pk)
{
    spx_ctx ctx;
    uint32_t counter = get_fors_counter(signature);
    if (counter == 0) {
        return -1;
    }
    memcpy(ctx.pub_seed, pk, SPX_N);
    memset(ctx.sk_seed, 0, SPX_N);
    return hash_message(digest, tree, leaf, signature, pk, message,
                        message_len, &ctx, &counter);
}

static int run_worker(unsigned int worker, const uint8_t *pk, const uint8_t *sk)
{
    char hit_path[128];
    char log_path[128];
    snprintf(hit_path, sizeof(hit_path), "attack_work/hits-%02u.bin", worker);
    snprintf(log_path, sizeof(log_path), "attack_work/queries-%02u.csv", worker);

    FILE *hits = fopen(hit_path, "wb");
    FILE *log = fopen(log_path, "w");
    if (!hits || !log) {
        die("worker output");
    }
    fprintf(log, "worker,query,message_len,sign_rc,siglen,fors_counter,leaf,tree\n");

    uint8_t worker_seed[64];
    derive_seed(worker_seed, sizeof(worker_seed),
                UINT64_C(0x4f50543235364658), worker);
    if (init_random_number(&drng_algorithm, worker_seed, sizeof(worker_seed)) != 0) {
        fprintf(stderr, "worker %u: DRNG init failed\n", worker);
        return 2;
    }

    unsigned int hit_count = 0;
    uint8_t message[64];
    uint8_t *signature = malloc(SPX_BYTES);
    if (!signature) {
        die("malloc signature");
    }

    for (unsigned int query = 0; query < QUERIES_PER_WORKER; query++) {
        int message_len = snprintf((char *)message, sizeof(message),
                                   "cedrusc-opt-256f-oracle-w%02u-q%03u",
                                   worker, query);
        size_t siglen = 0;
        int sign_rc = crypto_sign_signature(signature, &siglen, message,
                                            (size_t)message_len, sk);
        uint64_t tree = UINT64_MAX;
        uint32_t leaf = UINT32_MAX;
        uint8_t digest[SPX_FORS_MSG_BYTES];
        int parse_rc = -1;
        if (sign_rc == 0) {
            parse_rc = parse_signature(&tree, &leaf, digest, signature,
                                       message, (size_t)message_len, pk);
        }
        uint32_t forked_counter = get_fors_counter(signature);
        fprintf(log, "%u,%u,%d,%d,%zu,%" PRIu32 ",%" PRIu32 ",%" PRIu64 "\n",
                worker, query, message_len, sign_rc, siglen, forked_counter,
                leaf, tree);

        if (sign_rc != 0 || parse_rc != 0 || leaf != 0) {
            continue;
        }

        hit_record record;
        memset(&record, 0, sizeof(record));
        record.magic = HIT_MAGIC;
        record.worker = worker;
        record.query = query;
        record.message_len = (uint32_t)message_len;
        record.forked_counter = forked_counter;
        record.leaf = leaf;
        memcpy(record.message, message, (size_t)message_len);
        memcpy(record.signature, signature, SPX_BYTES);
        if (fwrite(&record, sizeof(record), 1, hits) != 1) {
            die("write hit");
        }
        hit_count++;
    }

    fprintf(stderr, "worker=%u queries=%u hits=%u\n", worker,
            QUERIES_PER_WORKER, hit_count);
    free(signature);
    if (fclose(hits) != 0 || fclose(log) != 0) {
        die("close worker output");
    }
    return 0;
}

static void append_hit(hit_list *list, const hit_record *record)
{
    if (list->count == list->capacity) {
        size_t next = list->capacity ? list->capacity * 2 : 256;
        hit_record *items = realloc(list->items, next * sizeof(*items));
        if (!items) {
            die("realloc hits");
        }
        list->items = items;
        list->capacity = next;
    }
    list->items[list->count++] = *record;
}

static void load_hits(hit_list *list)
{
    for (unsigned int worker = 0; worker < WORKERS; worker++) {
        char path[128];
        snprintf(path, sizeof(path), "attack_work/hits-%02u.bin", worker);
        FILE *file = fopen(path, "rb");
        if (!file) {
            die(path);
        }
        hit_record record;
        while (fread(&record, sizeof(record), 1, file) == 1) {
            if (record.magic != HIT_MAGIC || record.leaf != 0 ||
                record.message_len > MAX_MESSAGE_BYTES) {
                fprintf(stderr, "invalid hit record in %s\n", path);
                exit(3);
            }
            append_hit(list, &record);
        }
        if (ferror(file)) {
            die("read hits");
        }
        fclose(file);
    }
}

static void write_file(const char *path, const void *bytes, size_t len)
{
    FILE *file = fopen(path, "wb");
    if (!file) {
        die(path);
    }
    if (len && fwrite(bytes, 1, len, file) != len) {
        die("write file");
    }
    if (fclose(file) != 0) {
        die("close file");
    }
}

static double monotonic_seconds(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        die("clock_gettime");
    }
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

int main(void)
{
    ensure_dir("attack_work");
    ensure_dir("outputs");

    uint8_t key_seed[CRYPTO_SEEDBYTES];
    derive_seed(key_seed, sizeof(key_seed), UINT64_C(0x4b45593235364658), 0);
    uint8_t pk[SPX_PK_BYTES];
    uint8_t sk[SPX_SK_BYTES];
    if (crypto_sign_seed_keypair(pk, sk, key_seed) != 0) {
        fprintf(stderr, "key generation failed\n");
        return 4;
    }
    write_file("outputs/public-key.bin", pk, sizeof(pk));
    write_file("outputs/key-seed.bin", key_seed, sizeof(key_seed));

    double start = monotonic_seconds();
    pid_t children[WORKERS];
    for (unsigned int worker = 0; worker < WORKERS; worker++) {
        pid_t pid = fork();
        if (pid < 0) {
            die("fork");
        }
        if (pid == 0) {
            int rc = run_worker(worker, pk, sk);
            _exit(rc);
        }
        children[worker] = pid;
    }

    int worker_failures = 0;
    for (unsigned int worker = 0; worker < WORKERS; worker++) {
        int status = 0;
        if (waitpid(children[worker], &status, 0) != children[worker] ||
            !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
            worker_failures++;
        }
    }
    double collection_end = monotonic_seconds();
    if (worker_failures != 0) {
        fprintf(stderr, "worker failures=%d\n", worker_failures);
        return 5;
    }

    hit_list hits = {0};
    load_hits(&hits);
    if (hits.count == 0) {
        fprintf(stderr, "no same-instance signatures retained\n");
        return 6;
    }

    uint8_t covered[SPX_FORS_TREES][1 << SPX_FORS_HEIGHT];
    unsigned int covered_count[SPX_FORS_TREES];
    memset(covered, 0, sizeof(covered));
    memset(covered_count, 0, sizeof(covered_count));

    for (size_t j = 0; j < hits.count; j++) {
        uint64_t tree;
        uint32_t leaf;
        uint8_t digest[SPX_FORS_MSG_BYTES];
        if (parse_signature(&tree, &leaf, digest, hits.items[j].signature,
                            hits.items[j].message, hits.items[j].message_len, pk) != 0 ||
            tree != 0 || leaf != 0) {
            fprintf(stderr, "retained record reparse failed at %zu\n", j);
            return 7;
        }
        uint32_t indices[SPX_FORS_TREES];
        message_to_indices(indices, digest);
        for (unsigned int i = 0; i < SPX_FORS_TREES; i++) {
            if (!covered[i][indices[i]]) {
                covered[i][indices[i]] = 1;
                covered_count[i]++;
            }
        }
    }

    double product = 1.0;
    for (unsigned int i = 0; i < SPX_FORS_TREES; i++) {
        product *= (double)covered_count[i] / (double)(1u << SPX_FORS_HEIGHT);
    }

    const uint8_t target_message[] =
        "256f-optimized-fresh-unqueried-message-20261113";
    const size_t target_len = sizeof(target_message) - 1;
    uint8_t *forged = malloc(SPX_BYTES);
    if (!forged) {
        die("malloc forged");
    }

    uint64_t candidate_count = 0;
    uint64_t raw_outputs = 0;
    uint64_t accepted_digest_count = 0;
    uint64_t leaf_zero_count = 0;
    int found = 0;
    uint32_t target_indices[SPX_FORS_TREES] = {0};
    unsigned int selected_record[SPX_FORS_TREES] = {0};
    uint8_t found_R[SPX_N];
    uint32_t found_counter = 0;
    const uint64_t MAX_CANDIDATES = UINT64_C(20000000);
    double search_start = monotonic_seconds();

    for (; candidate_count < MAX_CANDIDATES; candidate_count++) {
        uint8_t R[SPX_N];
        if (get_random_number(&drng_algorithm, R, SPX_N * 8) != 0) {
            fprintf(stderr, "fresh DRNG failed\n");
            return 8;
        }

        uint64_t tree = UINT64_MAX;
        uint32_t leaf = UINT32_MAX;
        uint8_t digest[SPX_FORS_MSG_BYTES];
        uint32_t counter = 0;
        spx_ctx ctx;
        memcpy(ctx.pub_seed, pk, SPX_N);
        memset(ctx.sk_seed, 0, SPX_N);
        int rc = hash_message(digest, &tree, &leaf, R, pk, target_message,
                              target_len, &ctx, &counter);
        raw_outputs += counter;
        if (rc != 0) {
            continue;
        }
        accepted_digest_count++;
        if (leaf != 0) {
            continue;
        }
        leaf_zero_count++;

        uint32_t indices[SPX_FORS_TREES];
        message_to_indices(indices, digest);
        int usable = 1;
        for (unsigned int i = 0; i < SPX_FORS_TREES && usable; i++) {
            usable = covered[i][indices[i]];
        }
        if (!usable) {
            continue;
        }

        for (unsigned int i = 0; i < SPX_FORS_TREES; i++) {
            target_indices[i] = indices[i];
            selected_record[i] = UINT32_MAX;
            for (size_t j = 0; j < hits.count; j++) {
                uint64_t old_tree;
                uint32_t old_leaf;
                uint8_t old_digest[SPX_FORS_MSG_BYTES];
                if (parse_signature(&old_tree, &old_leaf, old_digest,
                                    hits.items[j].signature,
                                    hits.items[j].message,
                                    hits.items[j].message_len, pk) != 0) {
                    return 9;
                }
                uint32_t old_indices[SPX_FORS_TREES];
                message_to_indices(old_indices, old_digest);
                if (old_tree == 0 && old_leaf == 0 && old_indices[i] == indices[i]) {
                    selected_record[i] = (unsigned int)j;
                    break;
                }
            }
            if (selected_record[i] == UINT32_MAX) {
                fprintf(stderr, "coverage/index disagreement at subtree %u\n", i);
                return 10;
            }
        }
        memcpy(found_R, R, sizeof(found_R));
        found_counter = counter;
        found = 1;
        break;
    }
    double search_end = monotonic_seconds();

    if (!found) {
        fprintf(stderr, "no covered fresh digest after %" PRIu64 " R candidates\n",
                candidate_count);
        return 11;
    }

    memcpy(forged, hits.items[0].signature, SPX_BYTES);
    memcpy(forged, found_R, SPX_N);
    save_fors_counter(found_counter, forged);
    const size_t forspath_offset = SPX_N + 4;
    const size_t block_bytes = (SPX_FORS_HEIGHT + 1u) * SPX_N;
    for (unsigned int i = 0; i < SPX_FORS_TREES; i++) {
        memcpy(forged + forspath_offset + i * block_bytes,
               hits.items[selected_record[i]].signature +
                   forspath_offset + i * block_bytes,
               block_bytes);
    }

    int positive_rc = crypto_sign_verify(forged, SPX_BYTES, target_message,
                                         target_len, pk);
    uint8_t *bad_sig = malloc(SPX_BYTES);
    uint8_t *bad_pk = malloc(SPX_PK_BYTES);
    uint8_t *bad_msg = malloc(target_len);
    if (!bad_sig || !bad_pk || !bad_msg) {
        die("malloc controls");
    }
    memcpy(bad_sig, forged, SPX_BYTES);
    bad_sig[100] ^= 1;
    int sig_control_rc = crypto_sign_verify(bad_sig, SPX_BYTES, target_message,
                                            target_len, pk);
    memcpy(bad_pk, pk, SPX_PK_BYTES);
    bad_pk[7] ^= 1;
    int pk_control_rc = crypto_sign_verify(forged, SPX_BYTES, target_message,
                                           target_len, bad_pk);
    memcpy(bad_msg, target_message, target_len);
    bad_msg[0] ^= 1;
    int msg_control_rc = crypto_sign_verify(forged, SPX_BYTES, bad_msg,
                                            target_len, pk);

    write_file("outputs/forged-signature.bin", forged, SPX_BYTES);
    write_file("outputs/fresh-message.bin", target_message, target_len);
    write_file("outputs/forged-R.bin", found_R, SPX_N);

    FILE *summary = fopen("outputs/summary.txt", "w");
    if (!summary) {
        die("summary");
    }
    fprintf(summary, "parameter_set=CEDRUS+C-256f\n");
    fprintf(summary, "implementation=Optimized_Implementation\n");
    fprintf(summary, "signature_bytes=%u\n", SPX_BYTES);
    fprintf(summary, "workers=%u\n", WORKERS);
    fprintf(summary, "queries_per_worker=%u\n", QUERIES_PER_WORKER);
    fprintf(summary, "total_queries=%u\n", WORKERS * QUERIES_PER_WORKER);
    fprintf(summary, "same_instance_records=%zu\n", hits.count);
    fprintf(summary, "target_tree=0\n");
    fprintf(summary, "target_leaf=0\n");
    fprintf(summary, "fresh_R_candidates=%" PRIu64 "\n", candidate_count + 1);
    fprintf(summary, "fresh_raw_xof_outputs=%" PRIu64 "\n", raw_outputs);
    fprintf(summary, "fresh_accepted_digests=%" PRIu64 "\n", accepted_digest_count);
    fprintf(summary, "fresh_leaf_zero_digests=%" PRIu64 "\n", leaf_zero_count);
    fprintf(summary, "coverage_product=%.17g\n", product);
    fprintf(summary, "found_fors_counter=%" PRIu32 "\n", found_counter);
    fprintf(summary, "positive_verify_rc=%d\n", positive_rc);
    fprintf(summary, "signature_bit_control_rc=%d\n", sig_control_rc);
    fprintf(summary, "public_key_bit_control_rc=%d\n", pk_control_rc);
    fprintf(summary, "message_bit_control_rc=%d\n", msg_control_rc);
    fprintf(summary, "collection_seconds=%.9f\n", collection_end - start);
    fprintf(summary, "fresh_search_seconds=%.9f\n", search_end - search_start);
    fprintf(summary, "total_seconds=%.9f\n", monotonic_seconds() - start);
    fprintf(summary, "fresh_message_len=%zu\n", target_len);
    for (unsigned int i = 0; i < SPX_FORS_TREES; i++) {
        fprintf(summary, "coverage[%u]=%u/256 selected_record=%u target_index=%u\n",
                i, covered_count[i], selected_record[i], target_indices[i]);
    }
    if (fclose(summary) != 0) {
        die("close summary");
    }

    printf("positive_rc=%d sig_control=%d pk_control=%d msg_control=%d "
           "hits=%zu candidates=%" PRIu64 " raw=%" PRIu64 "\n",
           positive_rc, sig_control_rc, pk_control_rc, msg_control_rc,
           hits.count, candidate_count + 1, raw_outputs);

    free(bad_sig);
    free(bad_pk);
    free(bad_msg);
    free(forged);
    free(hits.items);
    return positive_rc == 0 && sig_control_rc != 0 &&
                   pk_control_rc != 0 && msg_control_rc != 0
               ? 0
               : 12;
}
