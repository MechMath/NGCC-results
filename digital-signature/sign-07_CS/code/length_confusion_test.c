#define _POSIX_C_SOURCE 200809L

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>

#include "SIG_AlgorithmInstance.h"
#include "drng.h"

extern DRNG_ctx drng_algorithm;

static double elapsed_ms(struct timespec start, struct timespec end) {
    return (end.tv_sec - start.tv_sec) * 1000.0
         + (end.tv_nsec - start.tv_nsec) / 1000000.0;
}

int main(void) {
    uint8_t seed[64];
    unsigned char *pk = calloc(sig_get_pk_len_bytes(), 1);
    unsigned char *sk = calloc(sig_get_sk_len_bytes(), 1);
    unsigned char *sig = calloc(sig_get_sn_len_bytes(), 1);
    unsigned long long pk_len = 0, sk_len = 0, sig_len = 0;
    unsigned char message[1] = {0x41};
    const unsigned long long wrapped_len = (1ULL << 32) + 1ULL;
    struct timespec start, end;
    unsigned char *wrapped = mmap(NULL, (size_t)wrapped_len,
                                  PROT_READ | PROT_WRITE,
                                  MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE,
                                  -1, 0);

    if (!pk || !sk || !sig || wrapped == MAP_FAILED) return 2;
    wrapped[0] = 0x41;
    wrapped[wrapped_len - 1] = 0x5a;
    memset(seed, 0x5a, sizeof(seed));
    init_random_number(&drng_algorithm, seed, sizeof(seed) * 8);

    if (sig_keygen(pk, &pk_len, sk, &sk_len) != 0) return 3;
    if (sig_sign(sk, sk_len, message, 1, sig, &sig_len) != 0) return 4;

    printf("pk_len=%llu sk_len=%llu sig_len=%llu\n", pk_len, sk_len, sig_len);
    printf("verify_normal=%d\n",
           sig_verify(pk, pk_len, sig, sig_len, message, 1));
    clock_gettime(CLOCK_MONOTONIC, &start);
    printf("verify_wrapped_same_prefix=%d\n",
           sig_verify(pk, pk_len, sig, sig_len, wrapped, wrapped_len));
    clock_gettime(CLOCK_MONOTONIC, &end);
    printf("wrapped_verify_ms=%.3f\n", elapsed_ms(start, end));
    wrapped[0] = 0x42;
    printf("verify_wrapped_changed_prefix=%d\n",
           sig_verify(pk, pk_len, sig, sig_len, wrapped, wrapped_len));
    printf("declared_len=%llu narrowed_int=%d\n",
           wrapped_len, (int)wrapped_len);

    free(sig);
    free(sk);
    free(pk);
    munmap(wrapped, (size_t)wrapped_len);
    return 0;
}
