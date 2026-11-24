#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "api.h"

static unsigned char *read_file(const char *path, size_t expected, size_t *actual)
{
    FILE *file = fopen(path, "rb");
    if (!file) {
        perror(path);
        exit(2);
    }
    unsigned char *buffer = malloc(expected ? expected : 1);
    if (!buffer) {
        perror("malloc");
        exit(2);
    }
    *actual = fread(buffer, 1, expected, file);
    if (ferror(file) || fgetc(file) != EOF) {
        fprintf(stderr, "%s: wrong file length or read failure\n", path);
        exit(3);
    }
    fclose(file);
    return buffer;
}

int main(int argc, char **argv)
{
    if (argc != 4) {
        fprintf(stderr, "usage: %s PUBLIC_KEY SIGNATURE MESSAGE\n", argv[0]);
        return 64;
    }
    size_t pk_len;
    size_t sig_len;
    size_t message_len;
    unsigned char *pk = read_file(argv[1], SPX_PK_BYTES, &pk_len);
    unsigned char *signature = read_file(argv[2], SPX_BYTES, &sig_len);
    FILE *message_file = fopen(argv[3], "rb");
    if (!message_file) {
        perror(argv[3]);
        return 2;
    }
    if (fseek(message_file, 0, SEEK_END) != 0) {
        perror("fseek");
        return 2;
    }
    long message_size = ftell(message_file);
    if (message_size < 0 || fseek(message_file, 0, SEEK_SET) != 0) {
        perror("message size");
        return 2;
    }
    message_len = (size_t)message_size;
    unsigned char *message = malloc(message_len ? message_len : 1);
    if (!message || fread(message, 1, message_len, message_file) != message_len) {
        fprintf(stderr, "message read failed\n");
        return 3;
    }
    fclose(message_file);

    int rc = crypto_sign_verify(signature, sig_len, message, message_len, pk);
    printf("crypto_sign_verify_rc=%d pk_bytes=%zu signature_bytes=%zu message_bytes=%zu\n",
           rc, pk_len, sig_len, message_len);
    free(pk);
    free(signature);
    free(message);
    return rc == 0 ? 0 : 1;
}
