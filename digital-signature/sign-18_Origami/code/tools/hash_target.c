#include <stdio.h>

#include "../source/Implementations and Test_Vectors/Implementations/Reference_Implementation/Origami-128/origami_ref.c"

static int read_file(const char *path, unsigned char *buf, size_t len) {
    FILE *f = fopen(path, "rb");
    if (f == NULL) return -1;
    size_t got = fread(buf, 1, len, f);
    int extra = fgetc(f);
    fclose(f);
    return got == len && extra == EOF ? 0 : -1;
}

int main(int argc, char **argv) {
    unsigned char msg[56], salt[BYTES_SALT], digest[BYTES_DIGEST];
    gf_t target[ORIGAMI_M];
    if (argc != 3 ||
        read_file(argv[1], msg, sizeof(msg)) != 0 ||
        read_file(argv[2], salt, sizeof(salt)) != 0) {
        return 1;
    }
    if (pseudohash(BYTES_DIGEST * 8, msg, sizeof(msg) * 8ULL, digest) != 0)
        return 2;
    hash_to_field(target, digest, sizeof(digest), salt);
    printf("T");
    for (int i = 0; i < ORIGAMI_M; i++)
        printf(" %u", (unsigned)target[i]);
    printf("\n");
    return 0;
}
