#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "drng.h"
#include "SIG_AlgorithmInstance.h"

DRNG_ctx drng_algorithm;

static int write_file(const char *path, const void *p, size_t n) {
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    if (fwrite(p, 1, n, f) != n) { fclose(f); return -1; }
    return fclose(f);
}

static int read_file(const char *path, void *p, size_t n) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    size_t got = fread(p, 1, n, f);
    int extra = fgetc(f);
    fclose(f);
    return got == n && extra == EOF ? 0 : -1;
}

static int read_message(const char *path, void *p, size_t cap, size_t *n) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    *n = fread(p, 1, cap, f);
    int extra = fgetc(f);
    int err = ferror(f);
    fclose(f);
    return extra == EOF && !err ? 0 : -1;
}

static void fill_seed(unsigned char seed[64]) {
    for (unsigned i = 0; i < 64; i++) seed[i] = (unsigned char)(i * 37u + 11u);
}

int main(int argc, char **argv) {
    unsigned char pk[4096], sk[8192], sig[8192], seed[64], msg[256];
    unsigned long long pklen = sizeof(pk), sklen = sizeof(sk), siglen = sizeof(sig);
    fill_seed(seed);
    memset(msg, 0x5a, 32);

    if (argc == 3 && strcmp(argv[1], "gen") == 0) {
        init_random_number(&drng_algorithm, seed, sizeof(seed));
        if (sig_keygen(pk, &pklen, sk, &sklen) ||
            sig_sign(sk, sklen, msg, 32, sig, &siglen)) return 2;
        char p[512];
        int n;
        n = snprintf(p, sizeof(p), "%s.pk", argv[2]); if (n < 0 || write_file(p, pk, pklen)) return 3;
        n = snprintf(p, sizeof(p), "%s.sk", argv[2]); if (n < 0 || write_file(p, sk, sklen)) return 3;
        n = snprintf(p, sizeof(p), "%s.msg", argv[2]); if (n < 0 || write_file(p, msg, 32)) return 3;
        n = snprintf(p, sizeof(p), "%s.sig", argv[2]); if (n < 0 || write_file(p, sig, siglen)) return 3;
        printf("gen rc=0 pk=%llu sk=%llu sig=%llu\n", pklen, sklen, siglen);
        return 0;
    }

    if (argc == 3 && strcmp(argv[1], "verify") == 0) {
        char p[512];
        int n;
        size_t mlen;
        n = snprintf(p, sizeof(p), "%s.pk", argv[2]); if (n < 0 || read_file(p, pk, 1048)) { fprintf(stderr, "read %s\n", p); return 4; }
        n = snprintf(p, sizeof(p), "%s.msg", argv[2]); if (n < 0 || read_message(p, msg, sizeof(msg), &mlen)) { fprintf(stderr, "read %s\n", p); return 4; }
        n = snprintf(p, sizeof(p), "%s.sig", argv[2]); if (n < 0 || read_file(p, sig, 1504)) { fprintf(stderr, "read %s\n", p); return 4; }
        printf("verify rc=%d mlen=%zu\n", sig_verify(pk, 1048, sig, 1504, msg, mlen), mlen);
        return 0;
    }

    fprintf(stderr, "usage: %s gen PREFIX | verify PREFIX\n", argv[0]);
    return 1;
}
