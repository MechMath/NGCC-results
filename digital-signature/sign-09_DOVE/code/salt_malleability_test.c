#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "drng.h"
#include "SIG_AlgorithmInstance.h"

DRNG_ctx drng_algorithm;

int main(void) {
    unsigned char seed[64];
    unsigned char msg[32];
    memset(seed, 0x42, sizeof seed);
    memset(msg, 0xa5, sizeof msg);
    init_random_number(&drng_algorithm, seed, sizeof seed);

    unsigned long long pk_len = sig_get_pk_len_bytes();
    unsigned long long sk_len = sig_get_sk_len_bytes();
    unsigned long long sig_len = sig_get_sn_len_bytes();
    unsigned char *pk = calloc(pk_len, 1);
    unsigned char *sk = calloc(sk_len, 1);
    unsigned char *sig = calloc(sig_len, 1);
    if (!pk || !sk || !sig) return 2;

    if (sig_keygen(pk, &pk_len, sk, &sk_len) != 0) return 3;
    if (sig_sign(sk, sk_len, msg, sizeof msg, sig, &sig_len) != 0) return 4;
    int original = sig_verify(pk, pk_len, sig, sig_len, msg, sizeof msg);

    /* The last DOVE_SALT_BYTES bytes are the claimed salt. */
    for (size_t i = DOVE_N; i < sig_len; ++i) sig[i] ^= 0xff;
    int changed_salt = sig_verify(pk, pk_len, sig, sig_len, msg, sizeof msg);

    /* Restore the salt, then change a state byte to establish non-vacuity. */
    for (size_t i = DOVE_N; i < sig_len; ++i) sig[i] ^= 0xff;
    sig[0] ^= 0xff;
    int changed_state = sig_verify(pk, pk_len, sig, sig_len, msg, sizeof msg);

    printf("pk=%llu sk=%llu sig=%llu original=%d changed_salt=%d changed_state=%d\n",
           pk_len, sk_len, sig_len, original, changed_salt, changed_state);
    free(pk); free(sk); free(sig);
    return (original == 0 && changed_salt == 0 && changed_state != 0) ? 0 : 1;
}
