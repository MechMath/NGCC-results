#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "api.h"
#include "params.h"

static int check(const char *name, int expected, int actual)
{
    int ok = (expected == actual);
    printf("%-28s expected_rc=%d actual_rc=%d %s\n",
           name, expected, actual, ok ? "PASS" : "FAIL");
    return ok;
}

int main(void)
{
    uint8_t seed[CRYPTO_SEEDBYTES];
    uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[CRYPTO_SECRETKEYBYTES];
    uint8_t msg[32] = {0};
    uint8_t *sig;
    size_t siglen = 0, tforslen = 0;
    int rc = 1;
    size_t tfors_start, gwots_counter_offset;

    for (size_t i = 0; i < sizeof(seed); i++) seed[i] = (uint8_t)i;
    memset(msg, 0xA5, sizeof(msg));

    if (crypto_sign_seed_keypair(pk, sk, seed) != 0) {
        fprintf(stderr, "keygen failed\n");
        return 2;
    }

    sig = calloc(CRYPTO_BYTES + 1, 1);
    if (!sig) return 3;
    if (crypto_sign_signature(sig, &siglen, &tforslen,
                              msg, sizeof(msg), sk) != 0) {
        fprintf(stderr, "sign failed\n");
        free(sig);
        return 4;
    }

    printf("pk_bytes=%d sk_bytes=%d sig_max=%d sig_len=%zu tfors_len=%zu\n",
           CRYPTO_PUBLICKEYBYTES, CRYPTO_SECRETKEYBYTES,
           CRYPTO_BYTES, siglen, tforslen);
    rc &= check("honest_signature", 0,
                crypto_sign_verify(sig, siglen, msg, sizeof(msg), pk));

    tfors_start = SPX_N + COUNTER_SIZE + 2;
    gwots_counter_offset = tfors_start + tforslen +
                           SPX_GWOTS_BYTES + SPX_TREE_HEIGHT * SPX_N;

    sig[0] ^= 1;
    rc &= check("mutated_R_rejected", -1,
                crypto_sign_verify(sig, siglen, msg, sizeof(msg), pk));
    sig[0] ^= 1;

    sig[SPX_N] ^= 1;
    rc &= check("mutated_fors_counter", -1,
                crypto_sign_verify(sig, siglen, msg, sizeof(msg), pk));
    sig[SPX_N] ^= 1;

    sig[SPX_N + COUNTER_SIZE] ^= 0x18;
    rc &= check("mutated_tfors_len", -1,
                crypto_sign_verify(sig, siglen, msg, sizeof(msg), pk));
    sig[SPX_N + COUNTER_SIZE] ^= 0x18;

    sig[tfors_start] ^= 1;
    rc &= check("mutated_tfors_body", -1,
                crypto_sign_verify(sig, siglen, msg, sizeof(msg), pk));
    sig[tfors_start] ^= 1;

    sig[gwots_counter_offset] ^= 1;
    rc &= check("mutated_gwots_counter", -1,
                crypto_sign_verify(sig, siglen, msg, sizeof(msg), pk));
    sig[gwots_counter_offset] ^= 1;

    rc &= check("truncated_rejected", -1,
                crypto_sign_verify(sig, siglen - 1, msg, sizeof(msg), pk));
    rc &= check("extended_rejected", -1,
                crypto_sign_verify(sig, siglen + 1, msg, sizeof(msg), pk));

    msg[0] ^= 1;
    rc &= check("different_message_rejected", -1,
                crypto_sign_verify(sig, siglen, msg, sizeof(msg), pk));

    free(sig);
    printf("overall=%s\n", rc ? "PASS" : "FAIL");
    return rc ? 0 : 1;
}
