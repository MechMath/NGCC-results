#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "SIG_AlgorithmInstance.h"
#include "drng.h"

DRNG_ctx drng_algorithm;

static int write_u64(FILE *f, unsigned long long x) {
    return fwrite(&x, sizeof(x), 1, f) == 1;
}

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    static const unsigned long long lens[] = {0, 4096, 4097, 5000};
    unsigned char seed[64];
    unsigned long long pk_len = sig_get_pk_len_bytes();
    unsigned long long sk_len = sig_get_sk_len_bytes();
    unsigned long long sn_cap = sig_get_sn_len_bytes();
    unsigned char *pk = malloc((size_t)pk_len);
    unsigned char *sk = malloc((size_t)sk_len);
    unsigned char *sn = malloc((size_t)sn_cap);
    unsigned char *m = malloc(5001);
    if (!pk || !sk || !sn || !m) return 3;
    for (size_t i = 0; i < sizeof(seed); i++) seed[i] = (unsigned char)i;
    for (size_t i = 0; i < 5001; i++) m[i] = (unsigned char)(0xa5u ^ (17u * i));
    if (init_random_number(&drng_algorithm, seed, sizeof(seed)) != 0) return 4;
    if (sig_keygen(pk, &pk_len, sk, &sk_len) != 0) return 5;

    FILE *out = fopen(argv[1], "wb");
    if (!out) return 6;
    if (!write_u64(out, pk_len) || !write_u64(out, sk_len)) return 7;
    if (fwrite(pk, 1, (size_t)pk_len, out) != pk_len) return 8;
    if (fwrite(sk, 1, (size_t)sk_len, out) != sk_len) return 9;
    for (size_t i = 0; i < sizeof(lens) / sizeof(lens[0]); i++) {
        unsigned long long n = lens[i];
        unsigned long long sn_len = sn_cap;
        memset(sn, 0xcc, (size_t)sn_cap);
        int rc = sig_sign(sk, sk_len, m, n, sn, &sn_len);
        int self = rc == 0 ? sig_verify(pk, pk_len, sn, sn_len, m, n) : -99;
        if (!write_u64(out, n) || !write_u64(out, (unsigned long long)(int64_t)rc) ||
            !write_u64(out, sn_len) || !write_u64(out, (unsigned long long)(int64_t)self))
            return 10;
        if (fwrite(sn, 1, (size_t)sn_len, out) != sn_len) return 11;
        fprintf(stderr, "len=%llu rc=%d verify=%d siglen=%llu\n", n, rc, self, sn_len);
    }
    fclose(out);
    free(m); free(sn); free(sk); free(pk);
    return 0;
}
