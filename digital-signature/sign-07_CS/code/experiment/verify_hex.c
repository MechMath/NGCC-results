#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "SIG_AlgorithmInstance.h"

static int hex_nibble(char c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

static unsigned char *parse_hex(const char *hex, size_t *out_len)
{
    size_t hex_len = strlen(hex);
    unsigned char *out;

    if ((hex_len & 1U) != 0) {
        return NULL;
    }

    out = malloc(hex_len / 2);
    if (out == NULL) {
        return NULL;
    }

    for (size_t i = 0; i < hex_len / 2; i++) {
        int hi = hex_nibble(hex[2 * i]);
        int lo = hex_nibble(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) {
            free(out);
            return NULL;
        }
        out[i] = (unsigned char)((hi << 4) | lo);
    }

    *out_len = hex_len / 2;
    return out;
}

int main(int argc, char **argv)
{
    size_t pk_len = 0;
    size_t sig_len = 0;
    size_t msg_len = 0;
    unsigned char *pk;
    unsigned char *sig;
    unsigned char *msg;
    int result;

    if (argc != 4) {
        fprintf(stderr, "usage: %s PK_HEX SIG_HEX MSG_HEX\n", argv[0]);
        return 2;
    }

    pk = parse_hex(argv[1], &pk_len);
    sig = parse_hex(argv[2], &sig_len);
    msg = parse_hex(argv[3], &msg_len);
    if (pk == NULL || sig == NULL || msg == NULL) {
        fprintf(stderr, "invalid hexadecimal input\n");
        free(pk);
        free(sig);
        free(msg);
        return 2;
    }

    if (pk_len != sig_get_pk_len_bytes() ||
        sig_len != sig_get_sn_len_bytes()) {
        fprintf(stderr,
                "length mismatch: pk=%zu/%llu sig=%zu/%llu\n",
                pk_len,
                sig_get_pk_len_bytes(),
                sig_len,
                sig_get_sn_len_bytes());
        free(pk);
        free(sig);
        free(msg);
        return 2;
    }

    result = sig_verify(pk, pk_len, sig, sig_len, msg, msg_len);
    printf("sig_verify=%d\n", result);

    free(pk);
    free(sig);
    free(msg);
    return result == 0 ? 0 : 1;
}
