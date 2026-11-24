#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <time.h>

#include "api.h"
#include "context.h"
#include "counters.h"
#include "drng.h"
#include "hash.h"
#include "params.h"
#include "SIG_AlgorithmInstance.h"
#include "utils.h"

DRNG_ctx drng_algorithm;

#define MESSAGE_BYTES 16

static unsigned char leaf_of_signature(const unsigned char *sig,
                                       const unsigned char *pk,
                                       const unsigned char *msg,
                                       const unsigned char *sk)
{
    spx_ctx ctx = {0};
    unsigned char mhash[SPX_FORS_MSG_BYTES];
    uint64_t tree = ~(uint64_t)0;
    uint32_t leaf = UINT32_MAX;
    uint32_t counter = get_fors_counter(sig);

    memcpy(ctx.sk_seed, sk, SPX_N);
    memcpy(ctx.pub_seed, pk, SPX_N);
    initialize_hash_function(&ctx);
    if (hash_message(mhash, &tree, &leaf, sig, pk, msg, MESSAGE_BYTES,
                     &ctx, &counter) != 0) {
        return UINT32_MAX;
    }
    return (unsigned char)leaf;
}

int main(int argc, char **argv)
{
    if (argc != 5) {
        fprintf(stderr, "usage: %s WORKER_ID TRIALS TARGET_LEAF OUTPUT\n", argv[0]);
        return 2;
    }

    const unsigned int worker = (unsigned int)strtoul(argv[1], NULL, 0);
    const unsigned int trials = (unsigned int)strtoul(argv[2], NULL, 0);
    const unsigned int target_leaf = (unsigned int)strtoul(argv[3], NULL, 0);
    const char *output_path = argv[4];
    unsigned char key_seed[512] = {0};
    unsigned char sign_seed[512] = {0};
    unsigned char msg[MESSAGE_BYTES];
    unsigned char *pk = calloc(crypto_sign_publickeybytes(), 1);
    unsigned char *sk = calloc(crypto_sign_secretkeybytes(), 1);
    unsigned char *sig = calloc(crypto_sign_bytes(), 1);
    unsigned long long pk_len = 0, sk_len = 0, sig_len = 0;
    FILE *out;
    unsigned int hits = 0;
    unsigned int signing_failures = 0;
    struct timespec started, finished;
    struct rusage usage;

    for (int i = 0; i < 64; i++) {
        key_seed[i] = (unsigned char)(0x40 + i);
    }
    for (int i = 0; i < 64; i++) {
        sign_seed[i] = (unsigned char)(worker * 131u + i * 17u + 0xa5u);
    }

    init_random_number(&drng_algorithm, key_seed, 64);
    if (sig_keygen(pk, &pk_len, sk, &sk_len) != 0) {
        fprintf(stderr, "key generation failed\n");
        return 3;
    }
    init_random_number(&drng_algorithm, sign_seed, 64);
    clock_gettime(CLOCK_MONOTONIC, &started);

    out = fopen(output_path, "wb");
    if (!out) {
        perror(output_path);
        return 4;
    }
    if (fwrite(pk, 1, pk_len, out) != (size_t)pk_len) {
        return 5;
    }

    for (unsigned int j = 0; j < trials; j++) {
        uint64_t serial = ((uint64_t)worker << 32) | j;
        memset(msg, 0, sizeof(msg));
        memcpy(msg, &serial, sizeof(serial));
        msg[8] = (unsigned char)worker;
        msg[9] = (unsigned char)(worker >> 8);
        if (sig_sign(sk, sk_len, msg, sizeof(msg), sig, &sig_len) != 0) {
            signing_failures++;
            continue;
        }
        unsigned int leaf = leaf_of_signature(sig, pk, msg, sk);
        if (getenv("PRINT_LEAF")) {
            printf("serial=%llu leaf=%u\n", (unsigned long long)serial, leaf);
        }
        if (leaf == target_leaf) {
            if (fwrite(msg, 1, sizeof(msg), out) != sizeof(msg) ||
                fwrite(sig, 1, (size_t)sig_len, out) != (size_t)sig_len) {
                return 6;
            }
            hits++;
        }
    }
    fclose(out);
    clock_gettime(CLOCK_MONOTONIC, &finished);
    getrusage(RUSAGE_SELF, &usage);
    double elapsed = (double)(finished.tv_sec - started.tv_sec) +
                     (double)(finished.tv_nsec - started.tv_nsec) / 1e9;
    printf("worker=%u trials=%u signing_failures=%u target_leaf=%u hits=%u "
           "signature_bytes=%llu elapsed_seconds=%.6f max_rss_kb=%ld\n",
           worker, trials, signing_failures, target_leaf, hits, sig_len,
           elapsed, usage.ru_maxrss);
    free(sig);
    free(sk);
    free(pk);
    return 0;
}
