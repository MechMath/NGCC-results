#include "hash.h"
#include "auxfunc.h"
#include <stdio.h>
#include <string.h>

int main(void)
{
    unsigned char msg[2048];
    unsigned char a[32], b[32];
    for (size_t i = 0; i < sizeof(msg); i++) msg[i] = (unsigned char)(i * 131u + 17u);

    size_t mismatches = 0;
    for (size_t len = 0; len <= sizeof(msg); len++) {
        hash_digest(a, msg, len);
        sm3hash(256, msg, (unsigned long long)len * 8, b);
        if (memcmp(a, b, sizeof(a)) != 0) {
            printf("mismatch len=%zu ref=", len);
            for (size_t j = 0; j < 32; j++) printf("%02x", a[j]);
            printf(" adapter=");
            for (size_t j = 0; j < 32; j++) printf("%02x", b[j]);
            printf("\n");
            mismatches++;
        }
    }
    printf("lengths_checked=%zu mismatches=%zu\n", sizeof(msg) + 1, mismatches);
    return mismatches ? 1 : 0;
}
