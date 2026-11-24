#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "drng.h"
#include "SIG_AlgorithmInstance.h"
#include "symmetric.h"

DRNG_ctx drng_algorithm;

static int load(const char *path, unsigned char *p, size_t n) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    size_t got = fread(p, 1, n, f);
    int extra = fgetc(f);
    fclose(f);
    return got == n && extra == EOF ? 0 : -1;
}

static int store(const char *path, const unsigned char *p, size_t n) {
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    if (fwrite(p, 1, n, f) != n) { fclose(f); return -1; }
    return fclose(f);
}

static uint64_t get43(const unsigned char *a, unsigned bitpos) {
    uint64_t x = 0;
    for (unsigned j = 0; j < 43; j++) {
        unsigned k = bitpos + j;
        x |= (uint64_t)((a[k >> 3] >> (k & 7)) & 1u) << j;
    }
    return x;
}

static void put43(unsigned char *a, unsigned bitpos, uint64_t x) {
    for (unsigned j = 0; j < 43; j++) {
        unsigned k = bitpos + j;
        unsigned char mask = (unsigned char)(1u << (k & 7));
        if ((x >> j) & 1u) a[k >> 3] |= mask;
        else a[k >> 3] &= (unsigned char)~mask;
    }
}

int main(int argc, char **argv) {
    if (argc != 2) return 1;
    char path[512];
    unsigned char pk[1048], sk[1864], msg[256], sig[1504], mutpk[1048], mutsig[1504];
    unsigned long long mlen, siglen = sizeof(mutsig);
    snprintf(path, sizeof(path), "%s.pk", argv[1]);
    if (load(path, pk, sizeof(pk))) return 2;
    snprintf(path, sizeof(path), "%s.sk", argv[1]);
    if (load(path, sk, sizeof(sk))) return 2;
    snprintf(path, sizeof(path), "%s.msg", argv[1]);
    FILE *fm = fopen(path, "rb");
    if (!fm) return 2;
    mlen = fread(msg, 1, sizeof(msg), fm);
    int extra = fgetc(fm);
    fclose(fm);
    if (extra != EOF || mlen == 0) return 2;

    const uint64_t D = 1681, row4 = D * D * D * D, limit = UINT64_C(1) << 43;
    unsigned found = 0;
    int poly = 0;
    unsigned block = 0;
    memcpy(mutpk, pk, sizeof(pk));
    for (poly = 0; poly < 3; poly++) {
        for (block = 0; block < 64; block++) {
            unsigned bitpos = 8u * (16u + 344u * (unsigned)poly) + 43u * block;
            uint64_t y = get43(pk, bitpos);
            if (y + row4 < limit) {
                put43(mutpk, bitpos, y + row4);
                found = 1;
                break;
            }
        }
        if (found) break;
    }
    if (!found) return 3;

    unsigned char tr[32];
    bit_h256(tr, mutpk, sizeof(mutpk));
    memcpy(sk + 1064, tr, sizeof(tr));

    init_random_number(&drng_algorithm, (const unsigned char *)"rebind-test-seed", 16);
    if (sig_sign(sk, sizeof(sk), msg, mlen, mutsig, &siglen)) return 4;

    snprintf(path, sizeof(path), "%s.mutpk", argv[1]);
    if (store(path, mutpk, sizeof(mutpk))) return 5;
    snprintf(path, sizeof(path), "%s.mutsig", argv[1]);
    if (store(path, mutsig, siglen)) return 5;

    uint64_t y = get43(pk, 8u * (16u + 344u * (unsigned)poly) + 43u * block);
    printf("poly=%d block=%d old=%llu new=%llu added=%llu tr_sha_input_len=%zu\n",
           poly, block, (unsigned long long)y, (unsigned long long)(y + row4),
           (unsigned long long)row4, sizeof(mutpk));
    return 0;
}
