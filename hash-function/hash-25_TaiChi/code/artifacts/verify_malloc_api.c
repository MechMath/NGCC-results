#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "CryptHash_AlgorithmInstance.h"

void *__wrap_malloc(size_t size) {
    (void)size;
    return NULL;
}

int main(void) {
    static const unsigned char message[] = "abc";
    unsigned char digest[128];
    size_t i;

    memset(digest, 0xa5, sizeof(digest));
    int status = CryptHash(DIGEST_BIT_LENGTH, message, 24, digest);

    printf("status=%d digest_unchanged=", status);
    for (i = 0; i < sizeof(digest); ++i) {
        if (digest[i] != 0xa5) {
            printf("false\n");
            return 0;
        }
    }
    printf("true\n");
    return 0;
}
