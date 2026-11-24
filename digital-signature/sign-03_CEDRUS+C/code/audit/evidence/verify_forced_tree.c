#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "api.h"
#include "params.h"
#include "SIG_AlgorithmInstance.h"

static int read_file(const char *path, unsigned char *out, size_t bytes)
{
    FILE *f = fopen(path, "rb");
    if (!f) {
        perror(path);
        return 0;
    }
    size_t got = fread(out, 1, bytes, f);
    unsigned char extra = 0;
    int has_extra = fread(&extra, 1, 1, f) != 0;
    fclose(f);
    return got == bytes && !has_extra;
}

int main(int argc, char **argv)
{
    const char *dir = argc > 1 ? argv[1] : "experiments/oracle-records";
    char oracle_path[1200], message_path[1200], signature_path[1200];
    unsigned char pk[SPX_PK_BYTES];
    unsigned char message[16];
    unsigned char signature[SPX_BYTES];
    unsigned char tampered[SPX_BYTES];

    snprintf(oracle_path, sizeof(oracle_path), "%s/oracle-0.bin", dir);
    snprintf(message_path, sizeof(message_path), "%s/forged-message.bin", dir);
    snprintf(signature_path, sizeof(signature_path),
             "%s/forged-signature.bin", dir);

    FILE *oracle = fopen(oracle_path, "rb");
    if (!oracle || fread(pk, 1, sizeof(pk), oracle) != sizeof(pk)) {
        return 2;
    }
    fclose(oracle);
    if (!read_file(message_path, message, sizeof(message)) ||
        !read_file(signature_path, signature, sizeof(signature))) {
        return 3;
    }

    int forged = sig_verify(pk, sizeof(pk), signature, sizeof(signature),
                            message, sizeof(message));
    memcpy(tampered, signature, sizeof(tampered));
    tampered[sizeof(tampered) - 1] ^= 1;
    int bad_signature = sig_verify(pk, sizeof(pk), tampered, sizeof(tampered),
                                   message, sizeof(message));
    message[0] ^= 1;
    int bad_message = sig_verify(pk, sizeof(pk), signature, sizeof(signature),
                                 message, sizeof(message));

    printf("forged_verify_rc=%d bad_signature_rc=%d bad_message_rc=%d\n",
           forged, bad_signature, bad_message);
    return forged == 0 && bad_signature != 0 && bad_message != 0 ? 0 : 4;
}
