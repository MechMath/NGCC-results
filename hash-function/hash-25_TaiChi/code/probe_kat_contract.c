#include <stdio.h>
#include <string.h>

#include "CryptHash_AlgorithmInstance.c"

static unsigned char reverse_byte(unsigned char x)
{
    x = (unsigned char)((x & 0xf0U) >> 4 | (x & 0x0fU) << 4);
    x = (unsigned char)((x & 0xccU) >> 2 | (x & 0x33U) << 2);
    x = (unsigned char)((x & 0xaaU) >> 1 | (x & 0x55U) << 1);
    return x;
}

static void print_digest(const char *label, const unsigned char *digest)
{
    printf("%s=", label);
    for (int i = 0; i < DIGEST_BYTES; i++)
        printf("%02x", digest[i]);
    printf("\n");
}

int main(void)
{
    unsigned char raw = 0x80;
    unsigned char mapped = reverse_byte(raw);
    unsigned char direct[DIGEST_BYTES];
    unsigned char alternate[DIGEST_BYTES];

    memset(direct, 0, sizeof(direct));
    memset(alternate, 0, sizeof(alternate));
    CryptHash(DIGEST_BIT_LENGTH, &raw, 1, direct);
    CryptHash(DIGEST_BIT_LENGTH, &mapped, 1, alternate);

    printf("raw=80 bits=1 mapped=%02x\n", mapped);
    print_digest("kat_msb_first", direct);
    for (int i = 0; i < DIGEST_BYTES; i++)
        alternate[i] = reverse_byte(alternate[i]);
    print_digest("kat_lsb_first_rendered", alternate);
    return 0;
}
