#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int CryptHash(int digest_len_bits, const unsigned char *msg,
              unsigned long long msg_len_bits, unsigned char *digest);

int main(int argc, char **argv) {
    const int digest_bits = atoi(argv[1]);
    const unsigned long long msg_bits =
        (unsigned long long)strtoull(argv[2], NULL, 10);
    const unsigned bytes = (unsigned)((msg_bits + 7) / 8);
    unsigned char *msg = bytes ? malloc(bytes) : NULL;
    unsigned char digest[128];
    uint64_t state = UINT64_C(0x9e3779b97f4a7c15);
    unsigned i;

    if (bytes && msg == NULL) return 2;
    for (i = 0; i < bytes; ++i) {
        state = state * UINT64_C(6364136223846793005) + 1;
        msg[i] = (unsigned char)(state >> 56);
    }
    memset(digest, 0, sizeof(digest));
    if (CryptHash(digest_bits, msg, msg_bits, digest) != 0) return 3;
    for (i = 0; i < (unsigned)digest_bits / 8; ++i) {
        printf("%02x", digest[i]);
    }
    putchar('\n');
    free(msg);
    return 0;
}
