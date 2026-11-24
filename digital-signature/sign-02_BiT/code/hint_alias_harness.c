#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "drng.h"
#include "packing.h"
#include "params.h"
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
    unsigned char *repacked;
    unsigned long long pk_len;
    unsigned long long sk_len;
    unsigned long long sig_len;
    DRNG_ctx drng_seed;
    DRNG_ctx drng_msg;
    polyvecm1 z1;
    polyveck h;
    unsigned char challenge[BIT_CHALLENGEBYTES];
    unsigned long long hint_start;
    int alias_count = 0;
    int alias_offset = -1;
    int alias_old = -1;
    int alias_new = -1;
    int alias_verify = -1;
    int negative_new = -1;
    int negative_verify = -1;

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
    repacked = calloc(sig_len, 1);
    if (!pk || !sk || !sig || !mut || !repacked) return 5;

    if (sig_keygen(pk, &pk_len, sk, &sk_len) != 0) return 6;
    if (sig_sign(sk, sk_len, msg, sizeof(msg), sig, &sig_len) != 0) return 7;
    if (sig_verify(pk, pk_len, sig, sig_len, msg, sizeof(msg)) != 0) return 8;

    memset(&z1, 0, sizeof(z1));
    memset(&h, 0, sizeof(h));
    memset(challenge, 0, sizeof(challenge));
    if (unpack_sig(&z1, &h, challenge, sig) != 0) return 9;

    hint_start = sig_len - BIT_POLYVECK_H_BYTES;
    for (unsigned long long i = 0; i < BIT_POLYVECK_H_BYTES; i++) {
        int original = sig[hint_start + i];
        for (int b = 0; b < 256; b++) {
            if (b == original) continue;
            memcpy(mut, sig, sig_len);
            mut[hint_start + i] = (unsigned char)b;
            memset(&z1, 0, sizeof(z1));
            memset(&h, 0, sizeof(h));
            memset(challenge, 0, sizeof(challenge));
            if (unpack_sig(&z1, &h, challenge, mut) != 0) continue;
            memset(repacked, 0, sig_len);
            pack_sig(repacked, &z1, &h, challenge);
            if (memcmp(repacked, sig, sig_len) == 0) {
                printf("alias_pair offset=%llu old=%d new=%d\n",
                       i, original, b);
                alias_count++;
                if (alias_offset < 0) {
                    alias_offset = (int)i;
                    alias_old = original;
                    alias_new = b;
                }
            }
        }
    }

    if (alias_offset >= 0) {
        memcpy(mut, sig, sig_len);
        mut[hint_start + alias_offset] = (unsigned char)alias_new;
        alias_verify =
            sig_verify(pk, pk_len, mut, sig_len, msg, sizeof(msg)) == 0;

        negative_new = (alias_new + 1) & 0xff;
        memcpy(mut, sig, sig_len);
        mut[hint_start + alias_offset] = (unsigned char)negative_new;
        negative_verify =
            sig_verify(pk, pk_len, mut, sig_len, msg, sizeof(msg)) != 0;
    } else {
        memcpy(mut, sig, sig_len);
        negative_new = (sig[hint_start] + 1) & 0xff;
        mut[hint_start] = (unsigned char)negative_new;
        negative_verify =
            sig_verify(pk, pk_len, mut, sig_len, msg, sizeof(msg)) != 0;
    }

    printf("N=%d K=%d L=%d pk_len=%llu sig_len=%llu hint_start=%llu hint_bytes=%d\n",
           BIT_N, BIT_K, BIT_L, pk_len, sig_len, hint_start,
           BIT_POLYVECK_H_BYTES);
    printf("canonical_verify=1 single_byte_alias_count=%d alias_offset=%d "
           "alias_old=%d alias_new=%d alias_verify=%d "
           "negative_new=%d negative_verify_rejected=%d\n",
           alias_count, alias_offset, alias_old, alias_new, alias_verify,
           negative_new, negative_verify);

    free(repacked);
    free(mut);
    free(sig);
    free(sk);
    free(pk);
    return 0;
}
