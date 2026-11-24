#include <stdio.h>
#include <stdlib.h>

#include "../source/Implementations and Test_Vectors/Implementations/Reference_Implementation/Origami-128/origami_ref.c"

static int read_file(const char *path, unsigned char *buf, size_t len) {
    FILE *f = fopen(path, "rb");
    if (f == NULL) return -1;
    size_t got = fread(buf, 1, len, f);
    int extra = fgetc(f);
    fclose(f);
    return got == len && extra == EOF ? 0 : -1;
}

int main(void) {
    unsigned char pk[BYTES_PK], msg[56], sig[BYTES_SIGNATURE];
    unsigned char digest[BYTES_DIGEST];
    ph_expanded_PK pkx;
    if (read_file("pk.bin", pk, sizeof(pk)) != 0 ||
        read_file("msg.bin", msg, sizeof(msg)) != 0 ||
        read_file("sig.bin", sig, sizeof(sig)) != 0) return 1;
    if (pseudohash(BYTES_DIGEST * 8, msg, sizeof(msg) * 8ULL, digest) != 0) return 4;
    if (ORIGAMI_NAMESPACE(pk_expand)(&pkx, pk) != 0) return 2;
    int rc = ORIGAMI_NAMESPACE(verify)(&pkx, sig, digest, sizeof(digest));
    printf("%d\n", rc);
    ORIGAMI_NAMESPACE(pk_free)(&pkx);
    return rc == 0 ? 0 : 3;
}
