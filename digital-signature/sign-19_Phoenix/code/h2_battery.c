#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "SIG_AlgorithmInstance.h"
#include "counter.h"
#include "drng.h"
#include "hash.h"
#include "octopus.h"
#include "params.h"
#include "utils.h"

DRNG_ctx drng_algorithm;

static void hex(FILE *f, const unsigned char *p, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        fprintf(f, "%02x", p[i]);
    }
}

int main(int argc, char **argv)
{
    unsigned long trials = argc > 1 ? strtoul(argv[1], NULL, 10) : 256;
    const char *csv_path = argc > 2 ? argv[2] : "h2_battery.csv";
    if (trials == 0 || trials > 1000000) {
        fprintf(stderr, "usage: %s TRIALS [CSV]\n", argv[0]);
        return 2;
    }

    unsigned char seed[64];
    for (size_t i = 0; i < sizeof(seed); i++) {
        seed[i] = (unsigned char)(0xa5U ^ (17U * i));
    }
    if (init_random_number(&drng_algorithm, seed, sizeof(seed)) != 0) {
        fprintf(stderr, "DRNG init failed\n");
        return 3;
    }

    unsigned long long pk_len = sig_get_pk_len_bytes();
    unsigned long long sk_len = sig_get_sk_len_bytes();
    unsigned long long sn_cap = sig_get_sn_len_bytes();
    unsigned char *pk = calloc(1, (size_t)pk_len);
    unsigned char *sk = calloc(1, (size_t)sk_len);
    unsigned char *sn = malloc((size_t)sn_cap);
    unsigned char *mtmp = malloc(65536 + COUNTER_SIZE);
    unsigned char digest[SPX_TFORS_MSG_BYTES];
    uint32_t indices[SPX_TFORS_K];
    uint32_t auth_count = 0;
    uint64_t tree = 0;
    uint32_t leaf = 0;
    spx_ctx ctx;
    if (!pk || !sk || !sn || !mtmp) {
        fprintf(stderr, "allocation failed\n");
        return 4;
    }

    clock_t start = clock();
    int kr = sig_keygen(pk, &pk_len, sk, &sk_len);
    if (kr != 0) {
        fprintf(stderr, "keygen failed: %d\n", kr);
        return 5;
    }
    memcpy(ctx.pub_seed, pk, SPX_N);
    memcpy(ctx.sk_seed, sk, SPX_N);
    initialize_hash_function(&ctx);

    FILE *csv = fopen(csv_path, "w");
    if (!csv) {
        fprintf(stderr, "cannot open %s: %s\n", csv_path, strerror(errno));
        return 6;
    }
    fprintf(csv, "trial,msg_hex,keygen_ret,sign_ret,verify_ret,mutated_verify_ret,"
                 "siglen,fors_counter,h2_ret,tfors_siglen,auth_count,event,sign_seconds,verify_seconds\n");

    unsigned long event_count = 0, sign_fail = 0, verify_fail = 0;
    unsigned long auth_mismatch = 0, event_sign_fail = 0, event_verify_fail = 0;
    unsigned long event_mutated_accept = 0;

    for (unsigned long t = 0; t < trials; t++) {
        size_t mlen = 32;
        for (size_t i = 0; i < mlen; i++) {
            mtmp[i] = (unsigned char)((t * 131U + i * 29U + 7U) & 0xffU);
        }

        unsigned long long sn_len = sn_cap;
        clock_t s0 = clock();
        int sr = sig_sign(sk, sk_len, mtmp, mlen, sn, &sn_len);
        clock_t s1 = clock();
        int vr = sr == 0 ? sig_verify(pk, pk_len, sn, sn_len, mtmp, mlen) : -99;
        clock_t s2 = clock();
        int mv = -99;

        if (sr != 0) {
            sign_fail++;
        }
        if (vr != 0) {
            verify_fail++;
        }

        uint32_t fc = 0;
        int hr = -99;
        uint32_t tfors_len = 0;
        int event = 0;
        if (sr == 0 && sn_len >= SPX_N + COUNTER_SIZE) {
            fc = (uint32_t)bytes_to_ull(sn + SPX_N, COUNTER_SIZE);
            memcpy(mtmp + mlen, (unsigned char[COUNTER_SIZE]){0}, COUNTER_SIZE);
            ull_to_bytes(mtmp + mlen, COUNTER_SIZE, fc);
            hash_message(digest, &tree, &leaf, sn, pk, mtmp, mlen + COUNTER_SIZE, &ctx);
            memset(indices, 0xff, sizeof(indices));
            hr = h2_generate_indices(indices, digest, &ctx);
            event = (hr == -1);
            if (event) {
                event_count++;
            }
            octopus_compute_auth_count(indices, SPX_TFORS_K, &auth_count);
            tfors_len = SPX_TFORS_K * SPX_N + auth_count * SPX_N;
            tfors_len = (uint32_t)bytes_to_ull(sn + SPX_N + COUNTER_SIZE, 2);
            if (tfors_len != SPX_TFORS_K * SPX_N + auth_count * SPX_N) {
                auth_mismatch++;
            }

            unsigned char saved = sn[sn_len - 1];
            sn[sn_len - 1] ^= 1;
            mv = sig_verify(pk, pk_len, sn, sn_len, mtmp, mlen);
            sn[sn_len - 1] = saved;
            if (event && sr != 0) event_sign_fail++;
            if (event && vr != 0) event_verify_fail++;
            if (event && mv == 0) event_mutated_accept++;
        }

        fprintf(csv,
                "%lu,", t);
        hex(csv, mtmp, mlen);
        fprintf(csv,
                ",%d,%d,%d,%d,%llu,%" PRIu32 ",%d,%" PRIu32 ",%" PRIu32 ",%d,%.6f,%.6f\n",
                kr, sr, vr, mv, sn_len, fc, hr, tfors_len, auth_count, event,
                (double)(s1 - s0) / CLOCKS_PER_SEC,
                (double)(s2 - s1) / CLOCKS_PER_SEC);
        fflush(csv);
    }
    fclose(csv);

    printf("{\n");
    printf("  \"implementation\": \"%s\",\n", ALGORITHM_INSTANCE);
    printf("  \"trials\": %lu,\n", trials);
    printf("  \"seed_hex\": \"");
    hex(stdout, seed, sizeof(seed));
    printf("\",\n  \"public_key_hex\": \"");
    hex(stdout, pk, (size_t)pk_len);
    printf("\",\n  \"secret_key_hex\": \"");
    hex(stdout, sk, (size_t)sk_len);
    printf("\",\n  \"sign_failures\": %lu,\n", sign_fail);
    printf("  \"verify_failures_after_sign\": %lu,\n", verify_fail);
    printf("  \"h2_failure_events\": %lu,\n", event_count);
    printf("  \"h2_event_sign_failures\": %lu,\n", event_sign_fail);
    printf("  \"h2_event_verify_failures\": %lu,\n", event_verify_fail);
    printf("  \"h2_event_mutated_accepts\": %lu,\n", event_mutated_accept);
    printf("  \"tfors_length_auth_mismatches\": %lu,\n", auth_mismatch);
    printf("  \"elapsed_seconds\": %.6f,\n", (double)(clock() - start) / CLOCKS_PER_SEC);
    printf("  \"csv\": \"%s\"\n", csv_path);
    printf("}\n");
    return 0;
}
