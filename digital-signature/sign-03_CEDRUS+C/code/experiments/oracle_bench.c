#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "api.h"
#include "drng.h"
#include "SIG_AlgorithmInstance.h"

DRNG_ctx drng_algorithm;

int main(int argc, char **argv)
{
    const int trials = argc > 1 ? atoi(argv[1]) : 100;
    unsigned char seed[64] = {0};
    unsigned char *pk = calloc(crypto_sign_publickeybytes(), 1);
    unsigned char *sk = calloc(crypto_sign_secretkeybytes(), 1);
    unsigned char *sig = calloc(crypto_sign_bytes(), 1);
    unsigned char msg[32];
    unsigned long long pk_len = 0, sk_len = 0, sig_len = 0;
    clock_t begin, end;
    int ok = 1;

    for (int i = 0; i < 64; i++) {
        seed[i] = (unsigned char)i;
    }
    init_random_number(&drng_algorithm, seed, sizeof(seed) * 8);
    if (sig_keygen(pk, &pk_len, sk, &sk_len) != 0) {
        return 2;
    }

    begin = clock();
    for (int i = 0; i < trials; i++) {
        memset(msg, 0, sizeof(msg));
        memcpy(msg, &i, sizeof(i));
        if (sig_sign(sk, sk_len, msg, sizeof(msg), sig, &sig_len) != 0 ||
            sig_verify(pk, pk_len, sig, sig_len, msg, sizeof(msg)) != 0) {
            ok = 0;
            break;
        }
    }
    end = clock();

    printf("trials=%d ok=%d cpu_seconds=%.6f signature_bytes=%llu\n",
           trials, ok, (double)(end - begin) / CLOCKS_PER_SEC, sig_len);
    free(sig);
    free(sk);
    free(pk);
    return ok ? 0 : 3;
}
