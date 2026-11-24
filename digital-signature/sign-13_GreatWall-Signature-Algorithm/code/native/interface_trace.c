#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "SIG_AlgorithmInstance.h"
#include "drng.h"

DRNG_ctx drng_algorithm;

static int write_file(const char *path, const unsigned char *data, size_t len)
{
    FILE *f = fopen(path, "wb");
    if (!f)
        return 0;
    const int ok = fwrite(data, 1, len, f) == len;
    return fclose(f) == 0 && ok;
}

static int one_transaction(const char *prefix, int mode)
{
    unsigned char msg[15];
    for (size_t i = 0; i < sizeof(msg); ++i)
        msg[i] = (unsigned char)(0x40u + i);

    const unsigned long long pk_len_cap = sig_get_pk_len_bytes();
    const unsigned long long sk_len_cap = sig_get_sk_len_bytes();
    const unsigned long long sig_len_cap = sig_get_sn_len_bytes();
    unsigned char *pk = calloc(1, pk_len_cap);
    unsigned char *sk = calloc(1, sk_len_cap);
    unsigned char *sig1 = calloc(1, sig_len_cap);
    unsigned char *sig2 = calloc(1, sig_len_cap);
    if (!pk || !sk || !sig1 || !sig2)
        return 2;

    unsigned long long pk_len = 0, sk_len = 0, sig1_len = 0, sig2_len = 0;
    int ret_keygen = sig_keygen(pk, &pk_len, sk, &sk_len);
    int ret_sign1 = -99, ret_sign2 = -99, ret_verify1 = -99, ret_verify2 = -99;

    if (ret_keygen == 0) {
        unsigned char seed[64];
        for (size_t i = 0; i < sizeof(seed); ++i)
            seed[i] = (unsigned char)(0xa5u ^ i);
        if (mode == 2 && init_random_number(&drng_algorithm, seed, sizeof(seed)) != 0)
            ret_sign1 = -98;
        else
            ret_sign1 = sig_sign(sk, sk_len, msg, sizeof(msg), sig1, &sig1_len);
        ret_verify1 = sig_verify(pk, pk_len, sig1, sig1_len, msg, sizeof(msg));
        if (mode == 1) {
            ret_sign2 = sig_sign(sk, sk_len, msg, sizeof(msg), sig2, &sig2_len);
        } else {
            if (mode == 2 &&
                init_random_number(&drng_algorithm, seed, sizeof(seed)) != 0)
                ret_sign2 = -98;
            else
                ret_sign2 = sig_sign(sk, sk_len, msg, sizeof(msg), sig2, &sig2_len);
        }
        if (ret_sign2 == 0)
            ret_verify2 = sig_verify(pk, pk_len, sig2, sig2_len, msg, sizeof(msg));
    }

    char path[256];
    snprintf(path, sizeof(path), "%s.pk", prefix);
    const int wrote_pk = write_file(path, pk, (size_t)pk_len);
    snprintf(path, sizeof(path), "%s.sk", prefix);
    const int wrote_sk = write_file(path, sk, (size_t)sk_len);
    snprintf(path, sizeof(path), "%s.sig1", prefix);
    const int wrote_sig1 = write_file(path, sig1, (size_t)sig1_len);
    snprintf(path, sizeof(path), "%s.sig2", prefix);
    const int wrote_sig2 = write_file(path, sig2, (size_t)sig2_len);

    printf("keygen_ret=%d pk_len=%llu sk_len=%llu "
           "sign1_ret=%d sig1_len=%llu verify1_ret=%d "
           "sign2_ret=%d sig2_len=%llu verify2_ret=%d "
           "signatures_equal=%d writes=%d%d%d%d\n",
           ret_keygen, pk_len, sk_len, ret_sign1, sig1_len, ret_verify1,
           ret_sign2, sig2_len, ret_verify2,
           ret_sign1 == 0 && ret_sign2 == 0 &&
               sig1_len == sig2_len &&
               memcmp(sig1, sig2, (size_t)sig1_len) == 0,
           wrote_pk, wrote_sk, wrote_sig1, wrote_sig2);

    free(pk);
    free(sk);
    free(sig1);
    free(sig2);
    return ret_keygen == 0 && ret_sign1 == 0 && ret_verify1 == 0 &&
                   ret_sign2 == 0 && ret_verify2 == 0 &&
                   wrote_pk && wrote_sk && wrote_sig1 && wrote_sig2
               ? 0
               : 1;
}

int main(int argc, char **argv)
{
    if (argc != 3 || (strcmp(argv[1], "zero") != 0 &&
                      strcmp(argv[1], "consecutive") != 0 &&
                      strcmp(argv[1], "reset") != 0)) {
        fprintf(stderr, "usage: %s zero|consecutive|reset PREFIX\n", argv[0]);
        return 64;
    }
    const int mode = strcmp(argv[1], "consecutive") == 0
                         ? 1
                         : strcmp(argv[1], "reset") == 0 ? 2 : 0;
    return one_transaction(argv[2], mode);
}
