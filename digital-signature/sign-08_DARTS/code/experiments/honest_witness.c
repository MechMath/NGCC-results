#include <stdio.h>
#include <string.h>

#include "SIG_AlgorithmInstance.h"
#include "drng.h"

extern DRNG_ctx drng_algorithm;

static int write_file(const char *path, const unsigned char *data, size_t len)
{
    FILE *f = fopen(path, "wb");
    if (f == NULL) {
        return 1;
    }
    if (fwrite(data, 1, len, f) != len) {
        fclose(f);
        return 1;
    }
    return fclose(f) != 0;
}

int main(int argc, char **argv)
{
    unsigned char pk[4096];
    unsigned char sk[4096];
    unsigned char sig[4096];
    unsigned char seed[48];
    unsigned long long pk_len = 0;
    unsigned long long sk_len = 0;
    unsigned long long sig_len = 0;
    int rc;

    if (argc != 4) {
        fprintf(stderr, "usage: %s <message> <pk-out> <sig-out>\n", argv[0]);
        return 64;
    }

    memset(seed, 0x55, sizeof(seed));
    rc = init_random_number(&drng_algorithm, seed, sizeof(seed));
    if (rc != 0) {
        return 2;
    }
    rc = sig_keygen(pk, &pk_len, sk, &sk_len);
    if (rc != 0) {
        return 3;
    }
    rc = sig_sign(sk, sk_len, (unsigned char *)argv[1],
                  (unsigned long long)strlen(argv[1]), sig, &sig_len);
    if (rc != 0) {
        return 4;
    }
    if (write_file(argv[2], pk, (size_t)pk_len) != 0 ||
        write_file(argv[3], sig, (size_t)sig_len) != 0) {
        return 5;
    }

    printf("pk_bytes=%llu signature_bytes=%llu\n", pk_len, sig_len);
    return 0;
}
