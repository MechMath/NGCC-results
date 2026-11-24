#include <stdio.h>
#include <string.h>

#include "api.h"
#include "params.h"
#include "SIG_AlgorithmInstance.h"

static int read_exact(const char *path, unsigned char *out, size_t bytes)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return 0;
    size_t got = fread(out, 1, bytes, f);
    unsigned char extra;
    int has_extra = fread(&extra, 1, 1, f) != 0;
    fclose(f);
    return got == bytes && !has_extra;
}

int main(int argc, char **argv)
{
    unsigned char pk[SPX_PK_BYTES];
    unsigned char bad_pk[SPX_PK_BYTES];
    unsigned char signature[SPX_BYTES];
    unsigned char message[16];
    if (argc != 4)
        return 2;
    if (!read_exact(argv[2], message, sizeof(message)) ||
        !read_exact(argv[3], signature, sizeof(signature)))
        return 3;

    FILE *f = fopen(argv[1], "rb");
    if (!f || fread(pk, 1, sizeof(pk), f) != sizeof(pk))
        return 4;
    fclose(f);

    memcpy(bad_pk, pk, sizeof(pk));
    bad_pk[0] ^= 1;
    int accepted = sig_verify(pk, sizeof(pk), signature, sizeof(signature),
                              message, sizeof(message));
    int bad_public_key = sig_verify(bad_pk, sizeof(bad_pk), signature,
                                    sizeof(signature), message, sizeof(message));
    printf("accepted_rc=%d bad_public_key_rc=%d\n", accepted, bad_public_key);
    return accepted == 0 && bad_public_key != 0 ? 0 : 5;
}
