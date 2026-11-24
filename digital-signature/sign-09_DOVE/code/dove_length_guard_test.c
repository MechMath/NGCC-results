#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "drng.h"
#include "SIG_AlgorithmInstance.h"

DRNG_ctx drng_algorithm;

static void die(const char *what, int code) {
    fprintf(stderr, "%s: %d\n", what, code);
    exit(2);
}

int main(int argc, char **argv) {
    if (argc != 2 ||
        (strcmp(argv[1], "sign_exact") != 0 &&
         strcmp(argv[1], "sign_guard") != 0 &&
         strcmp(argv[1], "verify_truncated") != 0)) {
        fprintf(stderr, "usage: %s sign_exact|sign_guard|verify_truncated\n", argv[0]);
        return 64;
    }

    unsigned char drng_seed[64];
    unsigned char msg[32];
    memset(drng_seed, 0x42, sizeof drng_seed);
    memset(msg, 0xa5, sizeof msg);
    if (init_random_number(&drng_algorithm, drng_seed, sizeof drng_seed) != 0)
        die("init_random_number", -1);

    unsigned long long pk_len = sig_get_pk_len_bytes();
    unsigned long long sk_len = sig_get_sk_len_bytes();
    unsigned long long sig_len = sig_get_sn_len_bytes();
    unsigned char *pk = calloc((size_t)pk_len, 1);
    /*
     * In verify_truncated mode, the extra private-key storage is a positive
     * control for the independent signer over-read at SIG_AlgorithmInstance.c:168.
     * The declared sk_len remains the original supported length.
     */
    size_t sk_alloc_len = (size_t)sk_len;
    if (strcmp(argv[1], "verify_truncated") == 0)
        sk_alloc_len += (size_t)DOVE_V * (size_t)DOVE_O;
    unsigned char *sk = NULL;
    void *guard_map = NULL;
    size_t guard_map_len = 0;
    if (strcmp(argv[1], "sign_guard") == 0) {
        long page = sysconf(_SC_PAGESIZE);
        if (page <= 0 || (size_t)sk_len > (size_t)page)
            die("guard page size", -3);
        guard_map_len = (size_t)page * 2;
        guard_map = mmap(NULL, guard_map_len, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (guard_map == MAP_FAILED)
            die("mmap", -4);
        if (mprotect((unsigned char *)guard_map + page, (size_t)page, PROT_NONE) != 0)
            die("mprotect", -5);
        sk = (unsigned char *)guard_map + (size_t)page - (size_t)sk_len;
    } else {
        sk = calloc(sk_alloc_len, 1);
    }
    unsigned char *sig = calloc((size_t)sig_len, 1);
    if (!pk || !sk || !sig)
        die("allocation", -2);

    int rc = sig_keygen(pk, &pk_len, sk, &sk_len);
    if (rc != 0)
        die("sig_keygen", rc);
    rc = sig_sign(sk, sk_len, msg, sizeof msg, sig, &sig_len);
    if (rc != 0)
        die("sig_sign", rc);

    int exact = sig_verify(pk, pk_len, sig, sig_len, msg, sizeof msg);

    unsigned char *prefix = malloc((size_t)DOVE_N);
    if (!prefix)
        die("prefix allocation", -2);
    memcpy(prefix, sig, DOVE_N);
    int omitted_salt = sig_verify(pk, pk_len, prefix, DOVE_N, msg, sizeof msg);

    fprintf(stderr,
            "mode=%s N=%d S=%d exact=%d omitted_salt=%d next_length=%d\n",
            argv[1],
            DOVE_N, DOVE_SALT_BYTES, exact, omitted_salt, DOVE_N - 1);
    fflush(stderr);

    if (strcmp(argv[1], "sign_exact") == 0 ||
        strcmp(argv[1], "sign_guard") == 0) {
        free(prefix);
        free(sig);
        if (guard_map)
            munmap(guard_map, guard_map_len);
        else
            free(sk);
        free(pk);
        return 0;
    }

    unsigned char *short_sig = malloc((size_t)DOVE_N - 1);
    if (!short_sig)
        die("short allocation", -2);
    memcpy(short_sig, sig, (size_t)DOVE_N - 1);

    fprintf(stderr, "calling verify with declared/actual length %d\n", DOVE_N - 1);
    fflush(stderr);

    int truncated = sig_verify(pk, pk_len, short_sig, (unsigned long long)DOVE_N - 1,
                               msg, sizeof msg);
    printf("truncated=%d\n", truncated);

    free(short_sig);
    free(prefix);
    free(sig);
    free(sk);
    free(pk);
    return 0;
}
