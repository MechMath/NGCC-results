#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "api.h"
#include "params.h"

int main(int argc, char **argv) {
    const unsigned long trials = argc > 1 ? strtoul(argv[1], NULL, 10) : 40;
    unsigned char seed[CRYPTO_SEEDBYTES];
    unsigned char pk[SPX_PK_BYTES];
    unsigned char sk[SPX_SK_BYTES];
    unsigned char msg[32];
    unsigned char sig[SPX_BYTES];
    size_t siglen;
    size_t tfors_len;
    unsigned long sign_fail = 0;
    unsigned long verify_fail = 0;

    for (size_t i = 0; i < sizeof(seed); i++) {
        seed[i] = (unsigned char)(0x5aU ^ (unsigned char)i);
    }

    if (crypto_sign_seed_keypair(pk, sk, seed) != 0) {
        puts("keypair generation failed");
        return 2;
    }

    for (unsigned long t = 0; t < trials; t++) {
        memset(msg, 0, sizeof(msg));
        msg[0] = (unsigned char)t;
        msg[1] = (unsigned char)(t >> 8);
        msg[2] = (unsigned char)(t >> 16);
        msg[3] = (unsigned char)(t >> 24);

        siglen = 0;
        tfors_len = 0;
        int sr = crypto_sign_signature(sig, &siglen, &tfors_len,
                                       msg, sizeof(msg), sk);
        if (sr != 0) {
            sign_fail++;
            printf("trial=%lu sign_fail=%d siglen=%zu tfors_len=%zu\n",
                   t, sr, siglen, tfors_len);
            continue;
        }

        int vr = crypto_sign_verify(sig, siglen, msg, sizeof(msg), pk);
        if (vr != 0) {
            verify_fail++;
            printf("trial=%lu sign_ok verify_fail=%d siglen=%zu tfors_len=%zu\n",
                   t, vr, siglen, tfors_len);
        }
    }

    printf("SUMMARY trials=%lu sign_fail=%lu verify_fail_after_sign_ok=%lu\n",
           trials, sign_fail, verify_fail);
    return verify_fail == 0 ? 0 : 1;
}
