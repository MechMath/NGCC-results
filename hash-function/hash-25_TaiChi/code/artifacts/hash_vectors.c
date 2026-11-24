#include <stdio.h>
#include <string.h>

#include "CryptHash_AlgorithmInstance.h"

int main(void) {
    static const unsigned char message[] = "abc";
    unsigned char digest[128];
    size_t i;

    memset(digest, 0, sizeof(digest));
    int status = CryptHash(DIGEST_BIT_LENGTH, message, 24, digest);

    printf("status=%d digest=", status);
    for (i = 0; i < DIGEST_BIT_LENGTH / 8; ++i) {
        printf("%02x", digest[i]);
    }
    printf("\n");
    return 0;
}
