#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "drng.h"
#include "SIG_AlgorithmInstance.h"

DRNG_ctx drng_algorithm;

int main(void)
{
    unsigned char nonce_seed[64];
    unsigned char nonce_msg[64];
    unsigned char seed[64];
    unsigned char msg[56];
    unsigned char *pk;
    unsigned char *sk;
    unsigned char *sig;
    unsigned char *mut;
    unsigned long long pk_len;
    unsigned long long sk_len;
    unsigned long long sig_len;
    DRNG_ctx drng_seed;
    DRNG_ctx drng_msg;
    int eligible = 0;
    int accepted = 0;
    int negative_rejected = 0;
    unsigned long long accepted_offset = 0;

    memset(nonce_seed, 0, sizeof(nonce_seed));
    memset(nonce_msg, 0, sizeof(nonce_msg));
    for (int i = 0; i < 64 / 4; i++) memcpy(nonce_seed + 4 * i, "seed", 4);
    for (int i = 0; i < 64 / 3; i++) memcpy(nonce_msg + 3 * i, "msg", 3);
    memcpy(nonce_msg + 63, "m", 1);
    if (init_random_number(&drng_seed, nonce_seed, sizeof(nonce_seed)) != 0) return 2;
    if (init_random_number(&drng_msg, nonce_msg, sizeof(nonce_msg)) != 0) return 3;
    get_random_number(&drng_seed, seed, sizeof(seed) * 8);
    get_random_number(&drng_msg, msg, sizeof(msg) * 8);
    if (init_random_number(&drng_algorithm, seed, sizeof(seed)) != 0) return 4;

    pk_len = sig_get_pk_len_bytes();
    sk_len = sig_get_sk_len_bytes();
    sig_len = sig_get_sn_len_bytes();
    pk = calloc(pk_len, 1);
    sk = calloc(sk_len, 1);
    sig = calloc(sig_len, 1);
    mut = calloc(sig_len, 1);
    if (!pk || !sk || !sig || !mut) return 5;

    if (sig_keygen(pk, &pk_len, sk, &sk_len) != 0) return 6;
    if (sig_sign(sk, sk_len, msg, sizeof(msg), sig, &sig_len) != 0) return 7;
    if (sig_verify(pk, pk_len, sig, sig_len, msg, sizeof(msg)) != 0) return 8;

    memcpy(mut, sig, sig_len);
    for (unsigned long long i = 6080; i < sig_len; i++) {
        unsigned char b = sig[i];
        if (b <= 12) {
            eligible++;
            mut[i] = (unsigned char)(b + 243);
            if (sig_verify(pk, pk_len, mut, sig_len, msg, sizeof(msg)) == 0) {
                printf("accepted_offset=%llu old=%u new=%u\n", i, b, mut[i]);
                if (accepted_offset == 0) accepted_offset = i;
                accepted++;
            }
            mut[i] = b;
        }
    }

    memcpy(mut, sig, sig_len);
    if (accepted_offset != 0) {
        mut[accepted_offset] = (unsigned char)(sig[accepted_offset] + 1);
        negative_rejected =
            sig_verify(pk, pk_len, mut, sig_len, msg, sizeof(msg)) != 0;
    }

    printf("pk_len=%llu sk_len=%llu sig_len=%llu hint_start=6080\n",
           pk_len, sk_len, sig_len);
    printf("eligible=%d accepted=%d negative_plus_one_rejected=%d\n",
           eligible, accepted, negative_rejected);
    printf("offset6585=%u\n", sig[6585]);

    free(mut);
    free(sig);
    free(sk);
    free(pk);
    return 0;
}
