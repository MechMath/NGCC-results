#define _POSIX_C_SOURCE 200809L

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "SIG_AlgorithmInstance.h"
#include "drng.h"

extern DRNG_ctx drng_algorithm;

int main(void) {
    uint8_t seed[64];
    unsigned char byte = 0;
    unsigned char *pk = calloc(sig_get_pk_len_bytes(), 1);
    unsigned char *sk = calloc(sig_get_sk_len_bytes(), 1);
    unsigned char *sig = calloc(sig_get_sn_len_bytes(), 1);
    unsigned long long pk_len = 0, sk_len = 0, sig_len = 0;
    const unsigned long long hostile_len = 1ULL << 31;

    memset(seed, 0x5a, sizeof(seed));
    init_random_number(&drng_algorithm, seed, sizeof(seed) * 8);
    if (sig_keygen(pk, &pk_len, sk, &sk_len) != 0) return 3;
    if (sig_sign(sk, sk_len, &byte, 0, sig, &sig_len) != 0) return 4;

    printf("before_verify hostile_len=%llu narrowed_int=%d\n",
           hostile_len, (int)hostile_len);
    fflush(stdout);
    printf("verify_result=%d\n",
           sig_verify(pk, pk_len, sig, sig_len, &byte, hostile_len));

    free(sig);
    free(sk);
    free(pk);
    return 0;
}
