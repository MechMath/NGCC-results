#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static const uint32_t ROUND_CONSTANTS[16] = {
    0xB7E15162u, 0x8AED2A6Au, 0xBF715880u, 0x9CF4F3C7u,
    0x62E7160Fu, 0x38B4DA56u, 0xA784D904u, 0x5190CFEFu,
    0x324E7738u, 0x926CFBE5u, 0xF4BF8D8Du, 0x8C31D763u,
    0xDA06C80Au, 0xBB1185EBu, 0x4F7C7B57u, 0x57F59584u
};

static const unsigned SHIFTS[24] = {
    3, 16, 13, 26, 8, 29, 2, 23, 21, 18, 31, 28,
    10, 15, 4, 9, 7, 20, 17, 30, 12, 1, 6, 27
};

/* Entry p is the source index in the table on page 9. */
static const unsigned DERANGEMENT[24] = {
    4, 9, 18, 23, 8, 1, 22, 15, 12, 17, 6, 3,
    20, 5, 10, 19, 0, 21, 14, 11, 16, 13, 2, 7
};

static uint32_t rol32(uint32_t x, unsigned n) {
    return n ? (x << n) | (x >> (32 - n)) : x;
}

static uint32_t ror6(uint32_t x, unsigned n) {
    return ((x >> n) | (x << (6 - n))) & 0x3fu;
}

static uint32_t s6(uint32_t x) {
    return (x ^ ror6(x, 2) ^ (ror6(x, 1) & ror6(x, 3)) ^ 0x1bu) & 0x3fu;
}

static void subcolumn(uint32_t state[24]) {
    uint32_t result[24] = {0};
    for (unsigned col = 0; col < 32; ++col) {
        unsigned after_s6[24];
        for (unsigned c = 0; c < 4; ++c) {
            uint32_t x = 0;
            for (unsigned r = 0; r < 6; ++r)
                x |= ((state[4 * r + c] >> col) & 1u) << r;
            uint32_t y = s6(x);
            for (unsigned r = 0; r < 6; ++r)
                after_s6[4 * r + c] = (y >> r) & 1u;
        }

        unsigned shuffled[24];
        for (unsigned p = 0; p < 24; ++p)
            shuffled[p] = after_s6[DERANGEMENT[p]];

        for (unsigned r = 0; r < 6; ++r) {
            unsigned out[4];
            for (unsigned j = 0; j < 4; ++j) {
                out[j] = 0;
                for (unsigned i = 0; i < 4; ++i)
                    if (i != j)
                        out[j] ^= shuffled[4 * r + i];
            }
            for (unsigned j = 0; j < 4; ++j)
                result[4 * r + j] |= out[j] << col;
        }
    }
    memcpy(state, result, 24 * sizeof(uint32_t));
}

static void permute(uint32_t state[24]) {
    for (unsigned round = 0; round < 16; ++round) {
        subcolumn(state);
        for (unsigned i = 0; i < 24; ++i)
            state[i] = rol32(state[i], SHIFTS[i]);
        state[23] ^= ROUND_CONSTANTS[round];
    }
}

static uint32_t reverse32(uint32_t x) {
    x = ((x & 0x55555555u) << 1) | ((x >> 1) & 0x55555555u);
    x = ((x & 0x33333333u) << 2) | ((x >> 2) & 0x33333333u);
    x = ((x & 0x0f0f0f0fu) << 4) | ((x >> 4) & 0x0f0f0f0fu);
    x = ((x & 0x00ff00ffu) << 8) | ((x >> 8) & 0x00ff00ffu);
    return (x << 16) | (x >> 16);
}

static void llh256_one_byte(uint32_t out[8], int msb_position_first) {
    uint32_t s[24] = {0};
    uint32_t previous[24];
    const uint32_t length = 8;

    /*
     * Final 64 state positions are W22 (positions 0..31) and W23
     * (positions 32..63). Numeric word bit j is state position j.
     */
    if (!msb_position_first) {
        s[22] = length;
    } else {
        s[23] = reverse32(length);
    }

    /* One-byte M=00, followed by 248 one bits. */
    uint32_t block[8] = {
        0xffffff00u, 0xffffffffu, 0xffffffffu, 0xffffffffu,
        0xffffffffu, 0xffffffffu, 0xffffffffu, 0xffffffffu
    };

    memcpy(previous, s, sizeof previous);
    permute(s);
    for (unsigned i = 0; i < 8; ++i)
        s[i] ^= block[i];
    /* Absorb M || C(S_old), including the old-capacity feed-forward. */
    for (unsigned i = 8; i < 24; ++i)
        s[i] ^= previous[i];
    permute(s);
    memcpy(out, s, 8 * sizeof(uint32_t));
}

static void print_bits_bytewise_lsb_first(const uint32_t words[8]) {
    for (unsigned i = 0; i < 8; ++i)
        for (unsigned byte = 0; byte < 4; ++byte)
            printf("%02x", (words[i] >> (8 * byte)) & 0xffu);
}

int main(void) {
    uint32_t a[8], b[8];
    llh256_one_byte(a, 0);
    llh256_one_byte(b, 1);
    printf("A=");
    print_bits_bytewise_lsb_first(a);
    printf("\nB=");
    print_bits_bytewise_lsb_first(b);
    printf("\n");
    return 0;
}
