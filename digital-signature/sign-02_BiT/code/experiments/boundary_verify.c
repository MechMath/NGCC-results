#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "SIG_AlgorithmInstance.h"
#include "drng.h"

DRNG_ctx drng_algorithm;

static int read_u64(FILE *f, unsigned long long *x) {
    return fread(x, sizeof(*x), 1, f) == 1;
}

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    FILE *in = fopen(argv[1], "rb");
    if (!in) return 3;
    unsigned long long pk_len, sk_len, n, rc, sn_len, self;
    if (!read_u64(in, &pk_len) || !read_u64(in, &sk_len)) return 4;
    unsigned char *pk = malloc((size_t)pk_len);
    unsigned char *sk = malloc((size_t)sk_len);
    if (!pk || !sk) return 5;
    if (fread(pk, 1, (size_t)pk_len, in) != pk_len) return 6;
    if (fread(sk, 1, (size_t)sk_len, in) != sk_len) return 7;
    free(sk);
    static const unsigned long long lens[] = {0, 4096, 4097, 5000};
    for (size_t i = 0; i < sizeof(lens) / sizeof(lens[0]); i++) {
        if (!read_u64(in, &n) || !read_u64(in, &rc) || !read_u64(in, &sn_len) ||
            !read_u64(in, &self)) return 8;
        unsigned char *sn = malloc((size_t)sn_len);
        unsigned char *m = malloc(5001);
        if (!sn || !m) return 9;
        for (size_t j = 0; j < 5001; j++) m[j] = (unsigned char)(0xa5u ^ (17u * j));
        if (fread(sn, 1, (size_t)sn_len, in) != sn_len) return 10;
        int verify = sig_verify(pk, pk_len, sn, sn_len, m, n);
        printf("len=%llu sign_rc=%llu self=%llu cross=%d\n", n, rc, self, verify);
        free(m); free(sn);
    }
    free(pk);
    fclose(in);
    return 0;
}
