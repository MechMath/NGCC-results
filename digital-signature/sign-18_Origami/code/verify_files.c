#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "SIG_AlgorithmInstance.h"
#include "drng.h"

DRNG_ctx drng_algorithm;

#define MAX_BYTES (1024ULL * 1024ULL)

static unsigned char *read_file(const char *path, unsigned long long *length)
{
    FILE *stream = fopen(path, "rb");
    unsigned char *data;
    long end;

    if (stream == NULL) {
        fprintf(stderr, "fopen %s: %s\n", path, strerror(errno));
        exit(2);
    }
    if (fseek(stream, 0, SEEK_END) != 0 ||
        (end = ftell(stream)) < 0 ||
        fseek(stream, 0, SEEK_SET) != 0) {
        fprintf(stderr, "seek %s failed\n", path);
        exit(2);
    }
    if ((unsigned long long)end > MAX_BYTES) {
        fprintf(stderr, "%s is too large\n", path);
        exit(2);
    }
    data = malloc((size_t)end + 1);
    if (data == NULL) {
        fprintf(stderr, "malloc failed\n");
        exit(2);
    }
    if (fread(data, 1, (size_t)end, stream) != (size_t)end) {
        fprintf(stderr, "fread %s failed\n", path);
        exit(2);
    }
    fclose(stream);
    *length = (unsigned long long)end;
    return data;
}

int main(int argc, char **argv)
{
    unsigned char *pk;
    unsigned char *msg;
    unsigned char *sig;
    unsigned long long pk_len;
    unsigned long long msg_len;
    unsigned long long sig_len;
    int result;

    if (argc == 5 && strcmp(argv[1], "verify") == 0) {
        argv++;
        argc--;
    }
    if (argc != 4) {
        fprintf(stderr, "usage: %s PK MESSAGE SIGNATURE\n", argv[0]);
        return 2;
    }
    pk = read_file(argv[1], &pk_len);
    msg = read_file(argv[2], &msg_len);
    sig = read_file(argv[3], &sig_len);
    result = sig_verify(pk, pk_len, sig, sig_len, msg, msg_len);
    if (result != 0) {
        fprintf(stderr, "sig_verify rejected: %d\n", result);
    }
    printf("%d\n", result);
    free(sig);
    free(msg);
    free(pk);
    return result == 0 ? 0 : 1;
}
