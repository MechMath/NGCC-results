#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "api.h"
#include "params.h"

void randombytes(unsigned char *out, unsigned long long outlen)
{
    (void)out;
    (void)outlen;
    abort();
}

static int read_exact(const char *path, unsigned char *buf, size_t len)
{
    FILE *f = fopen(path, "rb");
    if (f == NULL) {
        return -1;
    }
    int ok = fread(buf, 1, len, f) == len && fgetc(f) == EOF;
    fclose(f);
    return ok ? 0 : -1;
}

int main(int argc, char **argv)
{
    static const char message[] = "forged-optimized-message01";
    unsigned char pk[SPX_PK_BYTES];
    unsigned char sig[SPX_BYTES];
    unsigned char msg[sizeof(message)];
    int rc;

    if (argc != 3) {
        fprintf(stderr, "usage: %s MODE SIGNATURE\n", argv[0]);
        return 64;
    }
    if (read_exact("optimized-pk.bin", pk, sizeof(pk)) != 0 ||
        read_exact(argv[2], sig, sizeof(sig)) != 0) {
        fprintf(stderr, "artifact length/read failure\n");
        return 65;
    }
    memcpy(msg, message, sizeof(message));
    if (strcmp(argv[1], "signature-mutation") == 0) {
        sig[SPX_BYTES - 1] ^= 1;
    } else if (strcmp(argv[1], "message-mutation") == 0) {
        msg[0] ^= 1;
    } else if (strcmp(argv[1], "valid") != 0) {
        return 64;
    }

    rc = crypto_sign_verify(sig, sizeof(sig), msg, sizeof(message) - 1, pk);
    printf("mode=%s verify_rc=%d pk_sha_input_bytes=%zu signature_bytes=%zu "
           "message_bytes=%zu\n",
           argv[1], rc, sizeof(pk), sizeof(sig), sizeof(message) - 1);
    return rc == 0 ? 0 : 1;
}
