#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static const uint64_t RC[24] = {
    0xB7E151628AED2A6AULL, 0xBF7158809CF4F3C7ULL,
    0x62E7160F38B4DA56ULL, 0xA784D9045190CFEFULL,
    0x324E7738926CFBE5ULL, 0xF4BF8D8D8C31D763ULL,
    0xDA06C80ABB1185EBULL, 0x4F7C7B5757F59584ULL,
    0x90CFD47D7C19BB42ULL, 0x158D9554F7B46BCEULL,
    0xD55C4D79FD5F24D6ULL, 0x613C31C3839A2DDFULL,
    0x8A9A276BCFBFA1C8ULL, 0x77C56284DAB79CD4ULL,
    0xC2B3293D20E9E5EAULL, 0xF02AC60ACC93ED87ULL,
    0x4422A52ECB238FEEULL, 0xE5AB6ADD835FD1A0ULL,
    0x753D0A8F78E537D2ULL, 0xB95BB79D8DCAEC64ULL,
    0x2C1E9F23B829B5C2ULL, 0x780BF38737DF8BB3ULL,
    0x00D01334A0D0BD86ULL, 0x45CBFA73A6160FFEULL,
};

static const unsigned SHIFTS[24] = {
    2, 25, 20, 51, 15, 40, 37, 6, 36, 63, 62, 33,
    1, 30, 31, 4, 38, 5, 8, 47, 19, 52, 57, 34,
};

static const unsigned DERANGEMENT[24] = {
    4, 9, 18, 23, 8, 1, 22, 15, 12, 17, 6, 3,
    20, 5, 10, 19, 0, 21, 14, 11, 16, 13, 2, 7,
};

static uint64_t ror6(uint64_t x, unsigned n) {
    return (x >> n) | (x << (6 - n));
}

static uint64_t rol64(uint64_t x, unsigned n) {
    return (x << n) | (x >> (64 - n));
}

static uint64_t s6(uint64_t x) {
    x &= 63;
    return (x ^ ror6(x, 2) ^ (ror6(x, 1) & ror6(x, 3)) ^ 0x1b) & 63;
}

static void subcolumn(uint64_t state[24]) {
    uint64_t result[24] = {0};
    for (unsigned col = 0; col < 64; ++col) {
        unsigned after_s6[24];
        for (unsigned c = 0; c < 4; ++c) {
            uint64_t x = 0;
            for (unsigned r = 0; r < 6; ++r)
                x |= ((state[4 * r + c] >> col) & 1u) << r;
            uint64_t y = s6(x);
            for (unsigned r = 0; r < 6; ++r)
                after_s6[4 * r + c] = (y >> r) & 1u;
        }

        unsigned shuffled[24];
        for (unsigned p = 0; p < 24; ++p)
            shuffled[p] = after_s6[DERANGEMENT[p]];

        for (unsigned r = 0; r < 6; ++r) {
            for (unsigned j = 0; j < 4; ++j) {
                unsigned out = shuffled[4 * r + ((j + 1) % 4)] ^
                               shuffled[4 * r + ((j + 2) % 4)] ^
                               shuffled[4 * r + ((j + 3) % 4)];
                result[4 * r + j] |= (uint64_t)out << col;
            }
        }
    }
    memcpy(state, result, sizeof result);
}

static void permute(uint64_t state[24]) {
    for (unsigned round = 0; round < 24; ++round) {
        subcolumn(state);
        for (unsigned i = 0; i < 24; ++i)
            state[i] = rol64(state[i], SHIFTS[i]);
        state[23] ^= RC[round];
    }
}

static uint64_t reverse64(uint64_t x) {
    x = ((x & 0x5555555555555555ULL) << 1) |
        ((x >> 1) & 0x5555555555555555ULL);
    x = ((x & 0x3333333333333333ULL) << 2) |
        ((x >> 2) & 0x3333333333333333ULL);
    x = ((x & 0x0f0f0f0f0f0f0f0fULL) << 4) |
        ((x >> 4) & 0x0f0f0f0f0f0f0f0fULL);
    x = ((x & 0x00ff00ff00ff00ffULL) << 8) |
        ((x >> 8) & 0x00ff00ff00ff00ffULL);
    x = ((x & 0x0000ffff0000ffffULL) << 16) |
        ((x >> 16) & 0x0000ffff0000ffffULL);
    return (x << 32) | (x >> 32);
}

static void llh512_one_byte(uint64_t out[8], int msb_position_first) {
    uint64_t state[24] = {0};
    uint64_t previous_capacity[24];
    const uint64_t length = 8;
    state[23] = msb_position_first ? reverse64(length) : length;

    uint64_t block[8] = {
        0xffffffffffffff00ULL,
        0xffffffffffffffffULL,
        0xffffffffffffffffULL,
        0xffffffffffffffffULL,
        0xffffffffffffffffULL,
        0xffffffffffffffffULL,
        0xffffffffffffffffULL,
        0xffffffffffffffffULL,
    };

    memcpy(previous_capacity, state, sizeof previous_capacity);
    permute(state);
    for (unsigned i = 0; i < 8; ++i)
        state[i] ^= block[i];
    for (unsigned i = 8; i < 24; ++i)
        state[i] ^= previous_capacity[i];
    permute(state);
    memcpy(out, state, 8 * sizeof(uint64_t));
}

static void print_lsb_first(const uint64_t words[8]) {
    for (unsigned i = 0; i < 8; ++i)
        for (unsigned byte = 0; byte < 8; ++byte)
            printf("%02x", (unsigned)((words[i] >> (8 * byte)) & 0xff));
}

int main(void) {
    uint64_t a[8], b[8];
    llh512_one_byte(a, 0);
    llh512_one_byte(b, 1);
    printf("A=");
    print_lsb_first(a);
    printf("\nB=");
    print_lsb_first(b);
    printf("\n");
    return 0;
}
