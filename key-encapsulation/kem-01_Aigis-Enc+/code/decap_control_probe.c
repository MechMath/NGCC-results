#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "api.h"

int main(void)
{
    uint8_t *pk = calloc(KEM_PUBLICKEYBYTES, 1);
#ifdef GUARDED_SK
    uint8_t *sk_alloc = calloc(KEM_SECRETKEYBYTES + 16, 1);
    uint8_t *sk = sk_alloc ? sk_alloc + 16 : NULL;
#else
    uint8_t *sk_alloc = calloc(KEM_SECRETKEYBYTES, 1);
    uint8_t *sk = sk_alloc;
#endif
#ifdef PADDED_INPUT
    uint8_t *ct = calloc(KEM_CIPHERTEXTBYTES + 16, 1);
    uint8_t *bad = calloc(KEM_CIPHERTEXTBYTES + 16, 1);
#else
    uint8_t *ct = calloc(KEM_CIPHERTEXTBYTES, 1);
    uint8_t *bad = calloc(KEM_CIPHERTEXTBYTES, 1);
#endif
    uint8_t *ss_enc = calloc(KEM_BYTES, 1);
    uint8_t *ss_good = calloc(KEM_BYTES, 1);
    uint8_t *ss_bad1 = calloc(KEM_BYTES, 1);
    uint8_t *ss_bad2 = calloc(KEM_BYTES, 1);
    uint8_t *reject_input = calloc(KEM_BYTES + KEM_CIPHERTEXTBYTES, 1);
    uint8_t *expected_reject = calloc(KEM_BYTES, 1);
    if (!pk || !sk || !ct || !bad || !ss_enc || !ss_good || !ss_bad1 || !ss_bad2)
        return 2;

    if (mkem_keygen(pk, sk) || mkem_enc(pk, ss_enc, ct))
        return 3;
    if (mkem_dec(sk, ct, ss_good))
        return 4;
    memcpy(bad, ct, KEM_CIPHERTEXTBYTES);
    bad[0] ^= 1;
    if (mkem_dec(sk, bad, ss_bad1))
        return 5;
    bad[0] ^= 3;
    if (mkem_dec(sk, bad, ss_bad2))
        return 6;

    memcpy(reject_input, sk + KEM_SECRETKEYBYTES - KEM_BYTES, KEM_BYTES);
    memcpy(reject_input + KEM_BYTES, bad, KEM_CIPHERTEXTBYTES);
    KDF(expected_reject, KEM_BYTES, reject_input,
        KEM_BYTES + KEM_CIPHERTEXTBYTES);

    printf("pk=%d sk=%d ct=%d ss=%d\n",
           KEM_PUBLICKEYBYTES, KEM_SECRETKEYBYTES,
           KEM_CIPHERTEXTBYTES, KEM_BYTES);
    printf("valid_control=%d bad1_vs_enc=%d bad2_vs_enc=%d bad1_vs_bad2=%d\n",
           memcmp(ss_good, ss_enc, KEM_BYTES) == 0,
           memcmp(ss_bad1, ss_enc, KEM_BYTES) != 0,
           memcmp(ss_bad2, ss_enc, KEM_BYTES) != 0,
           memcmp(ss_bad1, ss_bad2, KEM_BYTES) != 0);
    printf("bad2_equals_spec_reject=%d\n",
           memcmp(ss_bad2, expected_reject, KEM_BYTES) == 0);

    free(pk); free(sk_alloc); free(ct); free(bad);
    free(ss_enc); free(ss_good); free(ss_bad1); free(ss_bad2);
    free(reject_input); free(expected_reject);
    return 0;
}
