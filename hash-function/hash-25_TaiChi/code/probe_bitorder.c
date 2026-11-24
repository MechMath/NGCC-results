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

static void print_vector(const unsigned char *msg, unsigned long long msg_len_bits)
{
    unsigned char mapped[8] = {0};
    unsigned char first[DIGEST_BYTES];
    unsigned char second[DIGEST_BYTES];
    unsigned long long bytes = (msg_len_bits + 7) / 8;

    for (unsigned long long i = 0; i < bytes; i++) {
        mapped[i] = reverse_byte(msg[i]);
    }

    memset(first, 0, sizeof(first));
    memset(second, 0, sizeof(second));
    CryptHash(DIGEST_BIT_LENGTH, msg, msg_len_bits, first);
    CryptHash(DIGEST_BIT_LENGTH, mapped, msg_len_bits, second);

    printf("message=");
    for (unsigned long long i = 0; i < bytes; i++) {
        printf("%02x", msg[i]);
    }
    printf(" bits=%llu\n", msg_len_bits);
    printf("msb-first-per-byte=");
    for (int i = 0; i < DIGEST_BYTES; i++) {
        printf("%02x", first[i]);
    }
    printf("\nlsb-first-per-byte=");
    for (int i = 0; i < DIGEST_BYTES; i++) {
        printf("%02x", reverse_byte(second[i]));
    }
    printf("\n");
}

int main(void)
{
    static const unsigned char empty[] = {0};
    static const unsigned char abc[] = {'a', 'b', 'c'};
    static const unsigned char zero_one[] = {0x01};

    print_vector(empty, 0);
    print_vector(abc, 24);
    print_vector(zero_one, 8);
    return 0;
}
