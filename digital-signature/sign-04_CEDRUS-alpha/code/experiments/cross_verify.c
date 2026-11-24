#define _POSIX_C_SOURCE 200809L

#include <ctype.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "api.h"
#include "params.h"
#include "randombytes.h"

struct kat_entry {
    int count;
    unsigned char *seed;
    size_t seed_len;
    unsigned char *pk;
    size_t pk_len;
    unsigned char *sk;
    size_t sk_len;
    unsigned char *msg;
    size_t msg_len;
    unsigned char *sig;
    size_t sig_len;
};

void randombytes(unsigned char *x, unsigned long long xlen)
{
    memset(x, 0, (size_t)xlen);
}

static void fail(const char *message)
{
    fprintf(stderr, "FAIL: %s\n", message);
    exit(2);
}

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
    size_t hex_len = strlen(hex);
    unsigned char *out;

    if (hex_len % 2 != 0) {
        fail("odd-length hexadecimal field");
    }
    out = malloc(hex_len / 2 + 1);
    if (out == NULL) {
        fail("allocation failed");
    }
    for (size_t i = 0; i < hex_len / 2; i++) {
        int hi = hex_value((unsigned char)hex[2 * i]);
        int lo = hex_value((unsigned char)hex[2 * i + 1]);
        if (hi < 0 || lo < 0) {
            fail("invalid hexadecimal digit");
        }
        out[i] = (unsigned char)((hi << 4) | lo);
    }
    *out_len = hex_len / 2;
    return out;
}

static void replace_hex(unsigned char **dst, size_t *dst_len, const char *hex)
{
    free(*dst);
    *dst = decode_hex(hex, dst_len);
}

static void reset_entry(struct kat_entry *entry)
{
    free(entry->seed);
    free(entry->pk);
    free(entry->sk);
    free(entry->msg);
    free(entry->sig);
    memset(entry, 0, sizeof(*entry));
}

static void check_length(const char *label, size_t actual, size_t expected)
{
    if (actual != expected) {
        fprintf(stderr, "FAIL: %s length %zu, expected %zu\n",
                label, actual, expected);
        exit(2);
    }
}

static void verify_entry(const struct kat_entry *entry, const char *backend)
{
    int result;

    check_length("seed", entry->seed_len, 64);
    check_length("public key", entry->pk_len, SPX_PK_BYTES);
    check_length("secret key", entry->sk_len, SPX_SK_BYTES);
    check_length("message", entry->msg_len, (size_t)(56 + 8 * entry->count));
    check_length("signature", entry->sig_len, SPX_BYTES);

    result = crypto_sign_verify(entry->sig, entry->sig_len,
                                entry->msg, entry->msg_len, entry->pk);
    printf("backend=%s entry=%d seed_len=%zu pk_len=%zu sk_len=%zu "
           "m_len=%zu sig_len=%zu verdict=%s\n",
           backend, entry->count, entry->seed_len, entry->pk_len,
           entry->sk_len, entry->msg_len, entry->sig_len,
           result == 0 ? "ACCEPT" : "REJECT");
}

int main(int argc, char **argv)
{
    FILE *file;
    char *line = NULL;
    size_t line_capacity = 0;
    ssize_t line_len;
    struct kat_entry entry = {0};
    int saw_count = 0;
    int entries = 0;

    if (argc != 3) {
        fprintf(stderr, "usage: %s BACKEND KAT_FILE\n", argv[0]);
        return 2;
    }
    file = fopen(argv[2], "r");
    if (file == NULL) {
        fprintf(stderr, "cannot open %s: %s\n", argv[2], strerror(errno));
        return 2;
    }

    while ((line_len = getline(&line, &line_capacity, file)) >= 0) {
        char *separator;

        while (line_len > 0 &&
               (line[line_len - 1] == '\n' || line[line_len - 1] == '\r')) {
            line[--line_len] = '\0';
        }
        if (line_len == 0) {
            if (saw_count) {
                verify_entry(&entry, argv[1]);
                entries++;
                reset_entry(&entry);
                saw_count = 0;
            }
            continue;
        }

        separator = strstr(line, " = ");
        if (separator == NULL) {
            fail("malformed KAT line");
        }
        *separator = '\0';
        char *value = separator + 3;

        if (strcmp(line, "Count") == 0) {
            entry.count = atoi(value);
            saw_count = 1;
        } else if (strcmp(line, "Seed_Len") == 0) {
            check_length("declared seed", (size_t)strtoul(value, NULL, 10), 64);
        } else if (strcmp(line, "Seed") == 0) {
            replace_hex(&entry.seed, &entry.seed_len, value);
        } else if (strcmp(line, "PK_Len") == 0) {
            check_length("declared public key",
                         (size_t)strtoul(value, NULL, 10), SPX_PK_BYTES);
        } else if (strcmp(line, "PK") == 0) {
            replace_hex(&entry.pk, &entry.pk_len, value);
        } else if (strcmp(line, "SK_Len") == 0) {
            check_length("declared secret key",
                         (size_t)strtoul(value, NULL, 10), SPX_SK_BYTES);
        } else if (strcmp(line, "SK") == 0) {
            replace_hex(&entry.sk, &entry.sk_len, value);
        } else if (strcmp(line, "M_Len") == 0) {
            entry.msg_len = (size_t)strtoul(value, NULL, 10);
        } else if (strcmp(line, "M") == 0) {
            replace_hex(&entry.msg, &entry.msg_len, value);
        } else if (strcmp(line, "Sn_Len") == 0) {
            check_length("declared signature",
                         (size_t)strtoul(value, NULL, 10), SPX_BYTES);
        } else if (strcmp(line, "Sn") == 0) {
            replace_hex(&entry.sig, &entry.sig_len, value);
        } else {
            fail("unknown KAT field");
        }
    }

    if (saw_count) {
        verify_entry(&entry, argv[1]);
        entries++;
    }
    reset_entry(&entry);
    free(line);
    if (ferror(file)) {
        fail("read error");
    }
    fclose(file);
    if (entries != 10) {
        fprintf(stderr, "FAIL: saw %d entries, expected 10\n", entries);
        return 2;
    }
    return 0;
}
