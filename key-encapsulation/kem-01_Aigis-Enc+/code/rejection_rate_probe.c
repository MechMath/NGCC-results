#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "api.h"

int main(int argc, char **argv)
{
    unsigned long trials = argc > 1 ? strtoul(argv[1], NULL, 10) : 1000;
    unsigned long valid_ok = 0, same_key = 0, spec_reject = 0;
    uint8_t *pk = calloc(KEM_PUBLICKEYBYTES, 1);
    uint8_t *sk = calloc(KEM_SECRETKEYBYTES, 1);
    uint8_t *ct = calloc(KEM_CIPHERTEXTBYTES + 16, 1);
    uint8_t *bad = calloc(KEM_CIPHERTEXTBYTES + 16, 1);
    uint8_t *ss_enc = calloc(KEM_BYTES, 1);
    uint8_t *ss_good = calloc(KEM_BYTES, 1);
    uint8_t *ss_bad = calloc(KEM_BYTES, 1);
    uint8_t *reject_input = calloc(KEM_BYTES + KEM_CIPHERTEXTBYTES, 1);
    uint8_t *expected_reject = calloc(KEM_BYTES, 1);
    if (!pk || !sk || !ct || !bad || !ss_enc || !ss_good || !ss_bad ||
        !reject_input || !expected_reject)
        return 2;

    for (unsigned long t = 0; t < trials; t++) {
        if (mkem_keygen(pk, sk) || mkem_enc(pk, ss_enc, ct) ||
            mkem_dec(sk, ct, ss_good))
            return 3;
        valid_ok += memcmp(ss_enc, ss_good, KEM_BYTES) == 0;
        memcpy(bad, ct, KEM_CIPHERTEXTBYTES);
        bad[0] ^= 1;
        if (mkem_dec(sk, bad, ss_bad))
            return 4;
        same_key += memcmp(ss_enc, ss_bad, KEM_BYTES) == 0;

        memcpy(reject_input, sk + KEM_SECRETKEYBYTES - KEM_BYTES, KEM_BYTES);
        memcpy(reject_input + KEM_BYTES, bad, KEM_CIPHERTEXTBYTES);
        KDF(expected_reject, KEM_BYTES, reject_input,
            KEM_BYTES + KEM_CIPHERTEXTBYTES);
        spec_reject += memcmp(ss_bad, expected_reject, KEM_BYTES) == 0;
    }

    printf("trials=%lu valid_ok=%lu tampered_returns_challenge_key=%lu tampered_equals_spec_reject=%lu\n",
           trials, valid_ok, same_key, spec_reject);
    return valid_ok == trials ? 0 : 5;
}
