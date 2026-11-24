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

static unsigned char *decode_hex(const char *hex, size_t *out_len)
{
    size_t len = strlen(hex);
    unsigned char *out;
    size_t i;

    while (len > 0 && (hex[len - 1] == '\n' || hex[len - 1] == '\r')) {
        len--;
    }
    if ((len & 1) != 0) {
        return NULL;
    }
    out = malloc(len / 2);
    if (out == NULL && len != 0) {
        return NULL;
    }
    for (i = 0; i < len / 2; i++) {
        int hi = hex_value((unsigned char)hex[2 * i]);
        int lo = hex_value((unsigned char)hex[2 * i + 1]);
        if (hi < 0 || lo < 0) {
            free(out);
            return NULL;
        }
        out[i] = (unsigned char)((hi << 4) | lo);
    }
    *out_len = len / 2;
    return out;
}

static int value_after_prefix(const char *line, const char *prefix)
{
    return strncmp(line, prefix, strlen(prefix)) == 0;
}

int main(int argc, char **argv)
{
    FILE *f;
    char *line;
    size_t line_cap = 0;
    ssize_t line_len;
    unsigned char *pk = NULL;
    unsigned char *sig = NULL;
    unsigned char *msg = NULL;
    size_t pk_len = 0;
    size_t sig_len = 0;
    size_t msg_len = 0;
    size_t pk_cap = 0;
    size_t sig_cap = 0;
    size_t msg_cap = 0;
    unsigned long long expected_pk = crypto_sign_publickeybytes();
    unsigned long long expected_sig = crypto_sign_bytes();
    int count = -1;
    int entries = 0;
    int accepted = 0;
    int rejected = 0;

    if (argc != 2) {
        fprintf(stderr, "usage: %s KAT_FILE\n", argv[0]);
        return 2;
    }
    f = fopen(argv[1], "r");
    if (f == NULL) {
        perror("fopen");
        return 2;
    }

    while ((line_len = getline(&line, &line_cap, f)) >= 0) {
        unsigned char *decoded;
        size_t decoded_len;
        (void)line_len;

        if (value_after_prefix(line, "Count = ")) {
            if (pk_len != 0 && sig_len != 0 && msg_len != 0) {
                int rc = crypto_sign_verify(sig, sig_len, msg, msg_len, pk);
                printf("entry=%d pk_len=%zu sig_len=%zu msg_len=%zu verify=%d\n",
                       entries, pk_len, sig_len, msg_len, rc);
                if (rc == 0) {
                    accepted++;
                } else {
                    rejected++;
                }
                entries++;
            }
            count++;
            pk_len = sig_len = msg_len = 0;
        } else if (value_after_prefix(line, "PK = ")) {
            decoded = decode_hex(line + 5, &decoded_len);
            if (decoded == NULL || decoded_len != expected_pk) {
                fprintf(stderr, "bad PK on entry %d\n", count);
                return 3;
            }
            free(pk);
            pk = decoded;
            pk_len = decoded_len;
            pk_cap = decoded_len;
        } else if (value_after_prefix(line, "Sn = ")) {
            decoded = decode_hex(line + 5, &decoded_len);
            if (decoded == NULL || decoded_len != expected_sig) {
                fprintf(stderr, "bad Sn on entry %d\n", count);
                return 3;
            }
            free(sig);
            sig = decoded;
            sig_len = decoded_len;
            sig_cap = decoded_len;
        } else if (value_after_prefix(line, "M = ")) {
            decoded = decode_hex(line + 4, &decoded_len);
            if (decoded == NULL) {
                fprintf(stderr, "bad M on entry %d\n", count);
                return 3;
            }
            free(msg);
            msg = decoded;
            msg_len = decoded_len;
            msg_cap = decoded_len;
        }
    }

    if (pk_len != 0 && sig_len != 0 && msg_len != 0) {
        int rc = crypto_sign_verify(sig, sig_len, msg, msg_len, pk);
        printf("entry=%d pk_len=%zu sig_len=%zu msg_len=%zu verify=%d\n",
               entries, pk_len, sig_len, msg_len, rc);
        if (rc == 0) {
            accepted++;
        } else {
            rejected++;
        }
        entries++;
    }

    printf("summary entries=%d accepted=%d rejected=%d\n",
           entries, accepted, rejected);
    (void)pk_cap;
    (void)sig_cap;
    (void)msg_cap;
    free(line);
    free(pk);
    free(sig);
    free(msg);
    fclose(f);
    return entries > 0 ? 0 : 4;
}
