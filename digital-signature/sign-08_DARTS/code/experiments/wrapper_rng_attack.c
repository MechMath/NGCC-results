#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "SIG_AlgorithmInstance.h"
#include "params.h"

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

static int read_file(const char *path, unsigned char *data, size_t len)
{
    FILE *f = fopen(path, "rb");
    if (f == NULL) {
        return 1;
    }
    size_t got = fread(data, 1, len, f);
    fclose(f);
    return got != len;
}

int main(int argc, char **argv)
{
    unsigned char pk[4096];
    unsigned char sk[4096];
    unsigned char sig[4096];
    unsigned long long pk_len = 0;
    unsigned long long sk_len = 0;
    unsigned long long sig_len = 0;

    if (argc == 5 && strcmp(argv[1], "sign") == 0) {
        const char *message = argv[2];
        if (sig_keygen(pk, &pk_len, sk, &sk_len) != 0 ||
            sig_sign(sk, sk_len, (unsigned char *)message,
                     (unsigned long long)strlen(message), sig, &sig_len) != 0) {
            return 2;
        }
        if (write_file(argv[3], pk, (size_t)pk_len) != 0 ||
            write_file(argv[4], sig, (size_t)sig_len) != 0) {
            return 3;
        }
        printf("wrote pk=%llu sig=%llu\n", pk_len, sig_len);
        return 0;
    }

    if (argc == 5 && strcmp(argv[1], "verify") == 0) {
        if (read_file(argv[2], pk, CRYPTO_PUBLICKEYBYTES) != 0 ||
            read_file(argv[3], sig, CRYPTO_SIGNATUREBYTES) != 0) {
            return 4;
        }
        int rc = sig_verify(pk, CRYPTO_PUBLICKEYBYTES,
                            sig, CRYPTO_SIGNATUREBYTES,
                            (unsigned char *)argv[4],
                            (unsigned long long)strlen(argv[4]));
        printf("sig_verify=%d\n", rc);
        return rc == 0 ? 0 : 5;
    }

    fprintf(stderr,
            "usage: %s sign <message> <pk-out> <sig-out> | "
            "verify <pk-in> <sig-in> <message>\n",
            argv[0]);
    return 64;
}
