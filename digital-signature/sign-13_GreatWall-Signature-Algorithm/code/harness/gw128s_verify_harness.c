#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "SIG_AlgorithmInstance.h"
#include "api.h"
#include "drng.h"
#include "faest.h"

DRNG_ctx drng_algorithm;

static void die(const char *what)
{
    fprintf(stderr, "ERROR: %s: %s\n", what, strerror(errno));
    exit(2);
}

static void *xmalloc(size_t n)
{
    void *p = malloc(n == 0 ? 1 : n);
    if (p == NULL) {
        die("malloc");
    }
    return p;
}

static unsigned char *read_file(const char *path, size_t expected)
{
    FILE *f = fopen(path, "rb");
    if (f == NULL) {
        die(path);
    }
    unsigned char *buf = xmalloc(expected);
    size_t got = fread(buf, 1, expected, f);
    if (got != expected) {
        fprintf(stderr, "ERROR: %s: short read %zu/%zu\n", path, got, expected);
        exit(2);
    }
    int c = fgetc(f);
    if (c != EOF) {
        fprintf(stderr, "ERROR: %s: file longer than %zu bytes\n", path, expected);
        exit(2);
    }
    if (fclose(f) != 0) {
        die(path);
    }
    return buf;
}

static void write_file(const char *path, const void *buf, size_t n)
{
    FILE *f = fopen(path, "wb");
    if (f == NULL) {
        die(path);
    }
    if (fwrite(buf, 1, n, f) != n || fclose(f) != 0) {
        die(path);
    }
}

static uint64_t splitmix64(uint64_t *state)
{
    uint64_t z = (*state += UINT64_C(0x9e3779b97f4a7c15));
    z = (z ^ (z >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
    z = (z ^ (z >> 27)) * UINT64_C(0x94d049bb133111eb);
    return z ^ (z >> 31);
}

static void fill_random(unsigned char *p, size_t n, uint64_t seed)
{
    uint64_t s = seed;
    for (size_t i = 0; i < n; ++i) {
        p[i] = (unsigned char)(splitmix64(&s) >> 56);
    }
}

static int raw_verify(const unsigned char *pk, const unsigned char *sig,
                      const unsigned char *msg, size_t msg_len)
{
    const size_t sm_len = msg_len + FAEST_SIGNATURE_BYTES;
    unsigned char *sm = xmalloc(sm_len);
    memcpy(sm, msg, msg_len);
    memcpy(sm + msg_len, sig, FAEST_SIGNATURE_BYTES);
    const int ret = faest_verify(sm + msg_len, sm, msg_len, pk) ? 0 : -1;
    free(sm);
    return ret;
}

static void generate_case(const char *prefix)
{
    char path[512];
    const size_t pk_len_expected = sig_get_pk_len_bytes();
    const size_t sk_len_expected = sig_get_sk_len_bytes();
    const size_t sig_len_expected = sig_get_sn_len_bytes();
    const size_t msg_len = 15;
    if (pk_len_expected != CRYPTO_PUBLICKEYBYTES ||
        sk_len_expected != CRYPTO_SECRETKEYBYTES ||
        sig_len_expected != FAEST_SIGNATURE_BYTES) {
        fprintf(stderr, "ERROR: API size disagreement\n");
        exit(3);
    }

    unsigned char *pk = xmalloc(pk_len_expected);
    unsigned char *sk = xmalloc(sk_len_expected);
    unsigned char *msg = xmalloc(msg_len);
    unsigned char *sig = xmalloc(sig_len_expected);
    unsigned long long pk_len = 0;
    unsigned long long sk_len = 0;
    unsigned long long sig_len = 0;
    for (size_t i = 0; i < msg_len; ++i) {
        msg[i] = (unsigned char)i;
    }

    int rc_keygen = sig_keygen(pk, &pk_len, sk, &sk_len);
    int rc_sign = rc_keygen == 0
        ? sig_sign(sk, sk_len, msg, msg_len, sig, &sig_len)
        : -99;
    int rc_verify = rc_sign == 0
        ? sig_verify(pk, pk_len, sig, sig_len, msg, msg_len)
        : -99;

    printf("keygen_ret=%d pk_len=%llu sk_len=%llu\n",
           rc_keygen, pk_len, sk_len);
    printf("sign_ret=%d sig_len=%llu\n", rc_sign, sig_len);
    printf("verify_ret=%d\n", rc_verify);
    if (rc_keygen != 0 || rc_sign != 0 || rc_verify != 0) {
        return;
    }

    snprintf(path, sizeof(path), "%s.pk", prefix);
    write_file(path, pk, pk_len);
    snprintf(path, sizeof(path), "%s.sk", prefix);
    write_file(path, sk, sk_len);
    snprintf(path, sizeof(path), "%s.msg", prefix);
    write_file(path, msg, msg_len);
    snprintf(path, sizeof(path), "%s.sig", prefix);
    write_file(path, sig, sig_len);

    free(sig);
    free(msg);
    free(sk);
    free(pk);
}

static void make_case(unsigned strategy, uint64_t index, uint64_t seed,
                      unsigned char *sig, const unsigned char *valid_sig)
{
    const size_t n = FAEST_SIGNATURE_BYTES;
    memcpy(sig, valid_sig, n);

    if (strategy == 0) {
        memset(sig, 0, n);
    } else if (strategy == 1) {
        memset(sig, 0xff, n);
    } else if (strategy == 2) {
        const size_t bit = (size_t)index;
        if (bit >= n * 8) {
            fprintf(stderr, "ERROR: bit index out of range\n");
            exit(2);
        }
        sig[bit / 8] ^= (unsigned char)(1u << (bit % 8));
    } else if (strategy == 3) {
        const size_t byte = (size_t)(index / 4);
        const unsigned variant = (unsigned)(index % 4);
        if (byte >= n) {
            fprintf(stderr, "ERROR: byte index out of range\n");
            exit(2);
        }
        if (variant == 0) {
            sig[byte] = 0x00;
        } else if (variant == 1) {
            sig[byte] = 0xff;
        } else if (variant == 2) {
            sig[byte] ^= 0x01;
        } else {
            sig[byte] ^= 0x80;
        }
    } else if (strategy == 4) {
        const size_t offsets[] = {
            0,
            VOLE_COMMIT_SIZE,
            VOLE_COMMIT_SIZE + VOLE_CHECK_PROOF_BYTES,
            VOLE_COMMIT_SIZE + VOLE_CHECK_PROOF_BYTES + WITNESS_BITS / 8,
            VOLE_COMMIT_SIZE + VOLE_CHECK_PROOF_BYTES + WITNESS_BITS / 8 +
                QUICKSILVER_PROOF_BYTES,
            VOLE_COMMIT_SIZE + VOLE_CHECK_PROOF_BYTES + WITNESS_BITS / 8 +
                QUICKSILVER_PROOF_BYTES + VECTOR_COM_OPEN_SIZE,
            VOLE_COMMIT_SIZE + VOLE_CHECK_PROOF_BYTES + WITNESS_BITS / 8 +
                QUICKSILVER_PROOF_BYTES + VECTOR_COM_OPEN_SIZE + sizeof(block_secpar),
            n
        };
        const unsigned field = (unsigned)(index / 2);
        if (field + 1 >= sizeof(offsets) / sizeof(offsets[0])) {
            fprintf(stderr, "ERROR: field index out of range\n");
            exit(2);
        }
        memset(sig + offsets[field], (index % 2) ? 0xff : 0x00,
               offsets[field + 1] - offsets[field]);
    } else if (strategy == 5) {
        fill_random(sig, n, seed + UINT64_C(0xd1b54a32d192ed03) * index);
    } else if (strategy == 6) {
        /* Positive control: retain the honest signature byte-for-byte. */
    } else {
        fprintf(stderr, "ERROR: unknown strategy %u\n", strategy);
        exit(2);
    }
}

static void verify_one(const char *prefix, unsigned strategy, uint64_t index,
                       uint64_t seed, int do_raw)
{
    char path[512];
    unsigned char *pk = NULL;
    unsigned char *sig = NULL;
    unsigned char *msg = NULL;
    unsigned char *valid_sig = NULL;

    snprintf(path, sizeof(path), "%s.pk", prefix);
    pk = read_file(path, sig_get_pk_len_bytes());
    snprintf(path, sizeof(path), "%s.msg", prefix);
    msg = read_file(path, 15);
    snprintf(path, sizeof(path), "%s.sig", prefix);
    valid_sig = read_file(path, sig_get_sn_len_bytes());
    sig = xmalloc(sig_get_sn_len_bytes());
    make_case(strategy, index, seed, sig, valid_sig);

    const unsigned long long pk_len = sig_get_pk_len_bytes();
    const unsigned long long sig_len = sig_get_sn_len_bytes();
    const int rc = sig_verify(pk, pk_len, sig, sig_len, msg, 15);
    printf("strategy=%u index=%" PRIu64 " seed=%" PRIu64
           " pk_len=%llu sig_len=%llu wrapper_ret=%d",
           strategy, index, seed, pk_len, sig_len, rc);
    if (do_raw) {
        const int raw = raw_verify(pk, sig, msg, 15);
        printf(" raw_ret=%d wrapper_raw_agree=%d", raw, raw == rc);
    }
    putchar('\n');

    free(valid_sig);
    free(msg);
    free(sig);
    free(pk);
}

static void fuzz_range(const char *prefix, unsigned strategy, uint64_t start,
                       uint64_t count, uint64_t seed, uint64_t progress_every)
{
    char path[512];
    unsigned char *pk = read_file((snprintf(path, sizeof(path), "%s.pk", prefix),
                                  path), sig_get_pk_len_bytes());
    unsigned char *msg = read_file((snprintf(path, sizeof(path), "%s.msg", prefix),
                                   path), 15);
    unsigned char *valid_sig =
        read_file((snprintf(path, sizeof(path), "%s.sig", prefix), path),
                  sig_get_sn_len_bytes());
    unsigned char *sig = xmalloc(sig_get_sn_len_bytes());
    const unsigned long long pk_len = sig_get_pk_len_bytes();
    const unsigned long long sig_len = sig_get_sn_len_bytes();
    uint64_t accepted = 0;
    uint64_t other = 0;

    for (uint64_t i = 0; i < count; ++i) {
        const uint64_t index = start + i;
        make_case(strategy, index, seed, sig, valid_sig);
        const int rc = sig_verify(pk, pk_len, sig, sig_len, msg, 15);
        if (rc == 0) {
            ++accepted;
            printf("ACCEPT strategy=%u index=%" PRIu64 " seed=%" PRIu64 "\n",
                   strategy, index, seed);
        } else if (rc != -1) {
            ++other;
            printf("OTHER strategy=%u index=%" PRIu64 " seed=%" PRIu64
                   " ret=%d\n", strategy, index, seed, rc);
        }
        if (progress_every != 0 && (i + 1) % progress_every == 0) {
            fprintf(stderr,
                    "PROGRESS strategy=%u next=%" PRIu64
                    " tested=%" PRIu64 " accepted=%" PRIu64
                    " other=%" PRIu64 "\n",
                    strategy, index + 1, i + 1, accepted, other);
            fflush(stderr);
        }
    }
    fprintf(stderr,
            "SUMMARY strategy=%u start=%" PRIu64 " count=%" PRIu64
            " seed=%" PRIu64 " accepted=%" PRIu64 " other=%" PRIu64 "\n",
            strategy, start, count, seed, accepted, other);

    free(sig);
    free(valid_sig);
    free(msg);
    free(pk);
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr,
                "usage: %s generate PREFIX\n"
                "       %s verify ONE PREFIX STRATEGY INDEX SEED [raw]\n"
                "       %s fuzz PREFIX STRATEGY START COUNT SEED PROGRESS_EVERY\n",
                argv[0], argv[0], argv[0]);
        return 2;
    }
    if (strcmp(argv[1], "generate") == 0 && argc == 3) {
        generate_case(argv[2]);
        return 0;
    }
    if (strcmp(argv[1], "verify") == 0 && (argc == 7 || argc == 8)) {
        verify_one(argv[3], (unsigned)strtoul(argv[4], NULL, 0),
                   strtoull(argv[5], NULL, 0), strtoull(argv[6], NULL, 0),
                   argc == 8 && strcmp(argv[7], "raw") == 0);
        return 0;
    }
    if (strcmp(argv[1], "fuzz") == 0 && argc == 8) {
        fuzz_range(argv[2], (unsigned)strtoul(argv[3], NULL, 0),
                   strtoull(argv[4], NULL, 0), strtoull(argv[5], NULL, 0),
                   strtoull(argv[6], NULL, 0), strtoull(argv[7], NULL, 0));
        return 0;
    }
    fprintf(stderr, "ERROR: invalid command line; argv[1]=%s argc=%d\n",
            argv[1], argc);
    return 2;
}
