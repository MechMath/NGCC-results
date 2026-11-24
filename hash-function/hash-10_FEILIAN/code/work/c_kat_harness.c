#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "CryptHash_AlgorithmInstance.h"

static void run_case(const char *name, const unsigned char *message,
                     unsigned long long message_bits) {
    unsigned char digest[DIGEST_BIT_LENGTH / 8];
    memset(digest, 0, sizeof(digest));
    int rc = CryptHash(DIGEST_BIT_LENGTH, message, message_bits, digest);
    printf("%s rc=%d digest=", name, rc);
    for (size_t i = 0; i < sizeof(digest); i++) {
        printf("%02x", digest[i]);
    }
    putchar('\n');
}

int main(void) {
    const unsigned char abc[3] = {'a', 'b', 'c'};
    unsigned char a129[129];
    memset(a129, 'a', sizeof(a129));
    run_case("abc", abc, 24);
    run_case("a129", a129, 1032);
    return 0;
}
