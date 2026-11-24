#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "api.h"
#include "drng.h"

DRNG_ctx drng_algorithm;

static int hex_value(int c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    return -1;
}

static int read_hex_field(FILE *file, const char *prefix, const char *path,
                          const char *label, unsigned char **out,
                          unsigned long long *out_len)
{
    char line[40000];
    const size_t prefix_len = strlen(prefix);

    while (fgets(line, sizeof(line), file) != NULL) {
        char *hex;
        size_t hex_len;
        size_t i;

        if (strncmp(line, prefix, prefix_len) != 0) {
            continue;
        }
        hex = line + prefix_len;
        hex_len = strcspn(hex, "\r\n");
        if ((hex_len & 1u) != 0) {
            fprintf(stderr, "%s: odd-length hexadecimal field %s\n", path, label);
            return -1;
        }
        *out_len = (unsigned long long)(hex_len / 2u);
        *out = malloc(hex_len / 2u);
        if (*out == NULL) {
            fprintf(stderr, "allocation failed for %s\n", label);
            return -1;
        }
        for (i = 0; i < hex_len / 2u; ++i) {
            int hi = hex_value((unsigned char)hex[2u * i]);
            int lo = hex_value((unsigned char)hex[2u * i + 1u]);
            if (hi < 0 || lo < 0) {
                fprintf(stderr, "%s: invalid hexadecimal in %s\n", path, label);
                free(*out);
                *out = NULL;
                return -1;
            }
            (*out)[i] = (unsigned char)((hi << 4) | lo);
        }
        return 0;
    }

    fprintf(stderr, "%s: missing field %s\n", path, label);
    return -1;
}

int main(int argc, char **argv)
{
    FILE *file;
    unsigned char *pk = NULL;
    unsigned char *msg = NULL;
    unsigned char *sig = NULL;
    unsigned long long pk_len = 0;
    unsigned long long msg_len = 0;
    unsigned long long sig_len = 0;
    int verify_rc;

    if (argc != 2) {
        fprintf(stderr, "usage: %s KAT_SIG_FILE\n", argv[0]);
        return 2;
    }
    file = fopen(argv[1], "rb");
    if (file == NULL) {
        perror(argv[1]);
        return 2;
    }
    if (read_hex_field(file, "PK = ", argv[1], "PK", &pk, &pk_len) != 0 ||
        read_hex_field(file, "M = ", argv[1], "M", &msg, &msg_len) != 0 ||
        read_hex_field(file, "Sn = ", argv[1], "Sn", &sig, &sig_len) != 0) {
        fclose(file);
        free(pk);
        free(msg);
        free(sig);
        return 2;
    }
    fclose(file);

    verify_rc = crypto_sign_verify(sig, (size_t)sig_len, msg, (size_t)msg_len, pk);
    printf("PK_BYTES=%llu M_BYTES=%llu SIG_BYTES=%llu VERIFY_RC=%d\n",
           pk_len, msg_len, sig_len, verify_rc);

    free(pk);
    free(msg);
    free(sig);
    return verify_rc == 0 ? 0 : 1;
}
