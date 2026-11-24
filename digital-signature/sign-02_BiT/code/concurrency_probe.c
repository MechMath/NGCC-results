#define _GNU_SOURCE
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "SIG_AlgorithmInstance.h"
#include "drng.h"
#include "params.h"

#define MAX_THREADS 8
#define SIGN_ROUNDS 40
#define KEYGEN_TRIALS 400
#define KEYGEN_THREADS 8

DRNG_ctx drng_algorithm;

static pthread_barrier_t barrier;
static unsigned char pk[BIT_PUBLICKEYBYTES];
static unsigned char sk[BIT_SECRETKEYBYTES];
static unsigned char msg0[64];
static unsigned char msg1[64];
static unsigned char msg0_sig[BIT_SIGNBYTES];
static unsigned char msg1_sig[BIT_SIGNBYTES];
static unsigned long long pk_len;
static unsigned long long sk_len;
static unsigned long long msg0_sig_len;
static unsigned long long msg1_sig_len;
static int msg0_verify = -999;
static int msg1_verify = -999;

typedef struct {
    uint64_t across_message_verified;
    uint64_t own_verify_failed;
    uint64_t sign_failed;
    uint64_t short_sig;
    uint64_t duplicate_signatures;
} sign_stats;

typedef struct {
    unsigned char pk[BIT_PUBLICKEYBYTES];
    unsigned char sk[BIT_SECRETKEYBYTES];
    unsigned long long pk_len;
    unsigned long long sk_len;
    int rc;
} key_result;

typedef struct {
    int id;
    int message_id;
    sign_stats stats;
} sign_arg;

typedef struct {
    int id;
    key_result result;
} key_arg;

typedef struct {
    uint64_t verify_failed;
    uint64_t cross_accepted;
} verify_stats;

typedef struct {
    verify_stats stats;
} verify_arg;

static uint64_t fnv1a(const void *buf, size_t len) {
    const unsigned char *p = (const unsigned char *)buf;
    uint64_t h = UINT64_C(1469598103934665603);
    for (size_t i = 0; i < len; i++) {
        h ^= p[i];
        h *= UINT64_C(1099511628211);
    }
    return h;
}

static void fill_seed(unsigned char seed[64], unsigned tag) {
    for (size_t i = 0; i < 64; i++) {
        seed[i] = (unsigned char)(17U * (unsigned)i + 3U * tag + 11U);
    }
}

static void fill_message(unsigned char msg[64], unsigned tag) {
    for (size_t i = 0; i < 64; i++) {
        msg[i] = (unsigned char)(31U * (unsigned)i + tag);
    }
}

static void reset_rng(unsigned trial) {
    unsigned char seed[64];
    fill_seed(seed, trial);
    int rc = init_random_number(&drng_algorithm, seed, sizeof(seed));
    if (rc != 0) {
        fprintf(stderr, "init_random_number failed: %d\n", rc);
        exit(2);
    }
}

static void *sign_worker(void *opaque) {
    sign_arg *arg = (sign_arg *)opaque;
    unsigned char *m = arg->message_id == 0 ? msg0 : msg1;
    unsigned char *dst = arg->message_id == 0 ? msg0_sig : msg1_sig;
    unsigned char candidate[BIT_SIGNBYTES];
    unsigned char previous[BIT_SIGNBYTES];
    int have_previous = 0;

    pthread_barrier_wait(&barrier);
    for (unsigned r = 0; r < SIGN_ROUNDS; r++) {
        unsigned long long candidate_len = 0;
        int rc = sig_sign(sk, sk_len, m, sizeof(msg0), candidate, &candidate_len);
        if (rc != 0) {
            arg->stats.sign_failed++;
            continue;
        }
        if (candidate_len != BIT_SIGNBYTES) {
            arg->stats.short_sig++;
            continue;
        }
        if (sig_verify(pk, pk_len, candidate, candidate_len, m, sizeof(msg0)) != 0)
            arg->stats.own_verify_failed++;

        unsigned char *other_m = arg->message_id == 0 ? msg1 : msg0;
        if (sig_verify(pk, pk_len, candidate, candidate_len, other_m, sizeof(msg0)) == 0)
            arg->stats.across_message_verified++;

        if (have_previous && memcmp(previous, candidate, BIT_SIGNBYTES) == 0)
            arg->stats.duplicate_signatures++;
        memcpy(previous, candidate, BIT_SIGNBYTES);
        have_previous = 1;

        if (r == SIGN_ROUNDS - 1)
            memcpy(dst, candidate, BIT_SIGNBYTES);
    }
    return NULL;
}

static void *key_worker(void *opaque) {
    key_arg *arg = (key_arg *)opaque;
    unsigned long long local_pk_len = 0;
    unsigned long long local_sk_len = 0;
    pthread_barrier_wait(&barrier);
    arg->result.rc = sig_keygen(arg->result.pk, &local_pk_len,
                                arg->result.sk, &local_sk_len);
    arg->result.pk_len = local_pk_len;
    arg->result.sk_len = local_sk_len;
    return NULL;
}

static void *verify_worker(void *opaque) {
    verify_arg *arg = (verify_arg *)opaque;
    unsigned char stable[BIT_SIGNBYTES];
    memcpy(stable, msg0_sig, BIT_SIGNBYTES);
    pthread_barrier_wait(&barrier);
    for (unsigned r = 0; r < SIGN_ROUNDS; r++) {
        if (sig_verify(pk, pk_len, stable, BIT_SIGNBYTES, msg0, sizeof(msg0)) != 0)
            arg->stats.verify_failed++;
        if (sig_verify(pk, pk_len, stable, BIT_SIGNBYTES, msg1, sizeof(msg1)) == 0)
            arg->stats.cross_accepted++;
    }
    return NULL;
}

static int make_base_key(void) {
    reset_rng(9001);
    pk_len = 0;
    sk_len = 0;
    if (sig_keygen(pk, &pk_len, sk, &sk_len) != 0)
        return -1;
    if (pk_len != BIT_PUBLICKEYBYTES || sk_len != BIT_SECRETKEYBYTES)
        return -2;
    return 0;
}

static void sequential_control(void) {
    reset_rng(9003);
    msg0_sig_len = 0;
    msg1_sig_len = 0;
    int s0 = sig_sign(sk, sk_len, msg0, sizeof(msg0), msg0_sig, &msg0_sig_len);
    int s1 = sig_sign(sk, sk_len, msg1, sizeof(msg1), msg1_sig, &msg1_sig_len);
    msg0_verify = s0 == 0 ? sig_verify(pk, pk_len, msg0_sig, msg0_sig_len,
                                      msg0, sizeof(msg0)) : -777;
    msg1_verify = s1 == 0 ? sig_verify(pk, pk_len, msg1_sig, msg1_sig_len,
                                      msg1, sizeof(msg1)) : -777;
    printf("sequential sign_rc=%d,%d verify_rc=%d,%d sig0=%016llx sig1=%016llx\n",
           s0, s1, msg0_verify, msg1_verify,
           (unsigned long long)fnv1a(msg0_sig, BIT_SIGNBYTES),
           (unsigned long long)fnv1a(msg1_sig, BIT_SIGNBYTES));
}

static void concurrent_sign_test(void) {
    int rc = make_base_key();
    if (rc != 0) {
        printf("base key generation failed rc=%d\n", rc);
        return;
    }
    reset_rng(9003);

    pthread_t threads[2];
    sign_arg args[2] = {{.id = 0, .message_id = 0}, {.id = 1, .message_id = 1}};
    pthread_barrier_init(&barrier, NULL, 2);
    pthread_create(&threads[0], NULL, sign_worker, &args[0]);
    pthread_create(&threads[1], NULL, sign_worker, &args[1]);
    pthread_join(threads[0], NULL);
    pthread_join(threads[1], NULL);
    pthread_barrier_destroy(&barrier);

    int v00 = sig_verify(pk, pk_len, msg0_sig, BIT_SIGNBYTES, msg0, sizeof(msg0));
    int v01 = sig_verify(pk, pk_len, msg0_sig, BIT_SIGNBYTES, msg1, sizeof(msg1));
    int v10 = sig_verify(pk, pk_len, msg1_sig, BIT_SIGNBYTES, msg0, sizeof(msg0));
    int v11 = sig_verify(pk, pk_len, msg1_sig, BIT_SIGNBYTES, msg1, sizeof(msg1));

    for (int i = 0; i < 2; i++) {
        printf("sign_thread=%d msg=%d sign_failed=%llu short_sig=%llu "
               "own_verify_failed=%llu cross_accepted=%llu duplicate_consecutive=%llu\n",
               args[i].id, args[i].message_id,
               (unsigned long long)args[i].stats.sign_failed,
               (unsigned long long)args[i].stats.short_sig,
               (unsigned long long)args[i].stats.own_verify_failed,
               (unsigned long long)args[i].stats.across_message_verified,
               (unsigned long long)args[i].stats.duplicate_signatures);
    }
    printf("final sig0_vs_m0=%d sig0_vs_m1=%d sig1_vs_m0=%d sig1_vs_m1=%d\n",
           v00, v01, v10, v11);
    printf("final hashes sig0=%016llx sig1=%016llx equal=%d\n",
           (unsigned long long)fnv1a(msg0_sig, BIT_SIGNBYTES),
           (unsigned long long)fnv1a(msg1_sig, BIT_SIGNBYTES),
           memcmp(msg0_sig, msg1_sig, BIT_SIGNBYTES) == 0);

    pthread_t phase2_threads[4];
    sign_arg phase2_signers[2] = {{.id = 2, .message_id = 0},
                                  {.id = 3, .message_id = 1}};
    verify_arg phase2_verifiers[2];
    memset(phase2_verifiers, 0, sizeof(phase2_verifiers));
    pthread_barrier_init(&barrier, NULL, 4);
    for (int i = 0; i < 2; i++)
        pthread_create(&phase2_threads[i], NULL, sign_worker, &phase2_signers[i]);
    for (int i = 0; i < 2; i++)
        pthread_create(&phase2_threads[2 + i], NULL, verify_worker,
                       &phase2_verifiers[i]);
    for (int i = 0; i < 4; i++)
        pthread_join(phase2_threads[i], NULL);
    pthread_barrier_destroy(&barrier);
    printf("mixed_sign_verify sign_failed=%llu sign_own_verify_failed=%llu "
           "verify_failed=%llu cross_accepted=%llu\n",
           (unsigned long long)(phase2_signers[0].stats.sign_failed +
                                phase2_signers[1].stats.sign_failed),
           (unsigned long long)(phase2_signers[0].stats.own_verify_failed +
                                phase2_signers[1].stats.own_verify_failed),
           (unsigned long long)(phase2_verifiers[0].stats.verify_failed +
                                phase2_verifiers[1].stats.verify_failed),
           (unsigned long long)(phase2_verifiers[0].stats.cross_accepted +
                                phase2_verifiers[1].stats.cross_accepted));
}

static void concurrent_keygen_test(void) {
    uint64_t identical_pk = 0;
    uint64_t identical_sk = 0;
    uint64_t failures = 0;
    uint64_t same_seed_prefix_observations = 0;
    unsigned first_trial = UINT32_MAX;
    int first_i = -1;
    int first_j = -1;
    key_result first_duplicate = {0};

    for (unsigned trial = 0; trial < KEYGEN_TRIALS; trial++) {
        reset_rng(10000 + trial);
        key_arg args[KEYGEN_THREADS];
        memset(args, 0, sizeof(args));
        pthread_t threads[KEYGEN_THREADS];
        for (int i = 0; i < KEYGEN_THREADS; i++)
            args[i].id = i;
        pthread_barrier_init(&barrier, NULL, KEYGEN_THREADS);
        for (int i = 0; i < KEYGEN_THREADS; i++)
            pthread_create(&threads[i], NULL, key_worker, &args[i]);
        for (int i = 0; i < KEYGEN_THREADS; i++)
            pthread_join(threads[i], NULL);
        pthread_barrier_destroy(&barrier);

        for (int i = 0; i < KEYGEN_THREADS; i++) {
            if (args[i].result.rc != 0 ||
                args[i].result.pk_len != BIT_PUBLICKEYBYTES ||
                args[i].result.sk_len != BIT_SECRETKEYBYTES) {
                failures++;
            }
        }
        for (int i = 0; i < KEYGEN_THREADS; i++) {
            for (int j = i + 1; j < KEYGEN_THREADS; j++) {
                if (args[i].result.rc != 0 || args[j].result.rc != 0)
                    continue;
                if (memcmp(args[i].result.pk, args[j].result.pk, BIT_PUBLICKEYBYTES) == 0)
                    identical_pk++;
                if (memcmp(args[i].result.sk, args[j].result.sk, BIT_SECRETKEYBYTES) == 0) {
                    identical_sk++;
                    if (first_trial == UINT32_MAX) {
                        first_trial = trial;
                        first_i = i;
                        first_j = j;
                        first_duplicate = args[i].result;
                    }
                }
                if (memcmp(args[i].result.sk, args[j].result.sk, 32) == 0)
                    same_seed_prefix_observations++;
            }
        }
    }
    printf("keygen_trials=%d keygen_threads=%d failures=%llu identical_pk_pairs=%llu "
           "identical_sk_pairs=%llu identical_first_32_sk_byte_pairs=%llu\n",
           KEYGEN_TRIALS, KEYGEN_THREADS, (unsigned long long)failures,
           (unsigned long long)identical_pk, (unsigned long long)identical_sk,
           (unsigned long long)same_seed_prefix_observations);
    if (first_trial != UINT32_MAX) {
        printf("first_duplicate trial=%u pair=(%d,%d) pk_hash=%016llx sk_hash=%016llx\n",
               first_trial, first_i, first_j,
               (unsigned long long)fnv1a(first_duplicate.pk, BIT_PUBLICKEYBYTES),
               (unsigned long long)fnv1a(first_duplicate.sk, BIT_SECRETKEYBYTES));
        FILE *fp = fopen("concurrent_duplicate_key.bin", "wb");
        if (fp != NULL) {
            fwrite(first_duplicate.pk, 1, BIT_PUBLICKEYBYTES, fp);
            fwrite(first_duplicate.sk, 1, BIT_SECRETKEYBYTES, fp);
            fclose(fp);
        }
    }
}

int main(void) {
    setbuf(stdout, NULL);
    fill_message(msg0, 1);
    fill_message(msg1, 2);
    printf("archive_sha256=698fbe834279a4100a66c20f3e0b634c738e1150936acf74b55efc6db6975e8d\n");
    printf("sizes pk=%llu sk=%llu sig=%llu\n",
           (unsigned long long)sig_get_pk_len_bytes(),
           (unsigned long long)sig_get_sk_len_bytes(),
           (unsigned long long)sig_get_sn_len_bytes());
    sequential_control();
    concurrent_sign_test();
    concurrent_keygen_test();
    return 0;
}
