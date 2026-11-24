#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "SIG_AlgorithmInstance.h"
#include "drng.h"
#include "rng.h"

DRNG_ctx drng_algorithm;

int main(int argc, char **argv)
{
    if (argc != 3 && argc != 4) {
        return 2;
    }

    if (argc == 4 && strcmp(argv[3], "--kat-context-only") == 0) {
        unsigned char seed[48];
        memset(seed, 0x5a, sizeof(seed));
        init_random_number(&drng_algorithm, seed, sizeof(seed));
    } else if (argc == 4) {
        unsigned char seed[48] = {0};
        FILE *seed_in = fopen(argv[3], "rb");
        if (!seed_in || fread(seed, 1, sizeof(seed), seed_in) != sizeof(seed)) {
            return 8;
        }
        fclose(seed_in);
        init_randombytes(seed, sizeof(seed));
    }

    unsigned long long pk_len = sig_get_pk_len_bytes();
    unsigned long long sk_len = sig_get_sk_len_bytes();
    unsigned long long sn_len = sig_get_sn_len_bytes();
    unsigned char *pk = calloc(pk_len, 1);
    unsigned char *sk = calloc(sk_len, 1);
    unsigned char *sn = calloc(sn_len, 1);
    const unsigned char msg[] = "repeatability-probe";
    if (!pk || !sk || !sn) {
        return 3;
    }

    if (sig_keygen(pk, &pk_len, sk, &sk_len) != 0) {
        return 4;
    }
    if (sig_sign(sk, sk_len, (unsigned char *)msg, sizeof(msg) - 1,
                 sn, &sn_len) != 0) {
        return 5;
    }
    if (sig_verify(pk, pk_len, sn, sn_len, (unsigned char *)msg,
                   sizeof(msg) - 1) != 0) {
        return 6;
    }

    FILE *pk_out = fopen(argv[1], "wb");
    FILE *sn_out = fopen(argv[2], "wb");
    char sk_path[4096];
    snprintf(sk_path, sizeof(sk_path), "%s.sk", argv[2]);
    FILE *sk_out = fopen(sk_path, "wb");
    if (!pk_out || !sn_out || !sk_out) {
        return 7;
    }
    fwrite(pk, 1, pk_len, pk_out);
    fwrite(sn, 1, sn_len, sn_out);
    fwrite(sk, 1, sk_len, sk_out);
    fclose(pk_out);
    fclose(sn_out);
    fclose(sk_out);
    free(pk);
    free(sk);
    free(sn);
    return 0;
}
