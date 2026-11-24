#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

static const int der[24] = {
    4, 9, 18, 23, 8, 1, 22, 15, 12, 17, 6, 3,
    20, 5, 10, 19, 0, 21, 14, 11, 16, 13, 2, 7
};

static uint8_t rol6(uint8_t x, unsigned r) {
    return (uint8_t)(((x << r) | (x >> (6 - r))) & 63);
}

static uint8_t s6(uint8_t x) {
    x &= 63;
    return (uint8_t)(x ^ rol6(x, 4) ^ (rol6(x, 5) & rol6(x, 3)) ^ 0x1b);
}

static uint32_t column_vector(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
    uint8_t values[4] = {a, b, c, d};
    uint32_t out = 0;
    for (unsigned col = 0; col < 4; col++)
        for (unsigned row = 0; row < 6; row++)
            out |= (uint32_t)(((values[col] >> row) & 1) << (4 * row + col));
    return out;
}

static uint32_t s24_linear(uint32_t pre) {
    uint32_t shuffled = 0, out = 0;
    for (unsigned bit = 0; bit < 24; bit++)
        shuffled |= (uint32_t)(((pre >> der[bit]) & 1) << bit);
    for (unsigned row = 0; row < 6; row++) {
        uint8_t bits = (uint8_t)((shuffled >> (4 * row)) & 15);
        uint8_t parity = (uint8_t)(__builtin_parity(bits));
        for (unsigned c = 0; c < 4; c++)
            out |= (uint32_t)((parity ^ ((bits >> c) & 1)) << (4 * row + c));
    }
    return out;
}

static uint32_t s24(uint32_t v) {
    uint8_t cols[4] = {0, 0, 0, 0};
    uint32_t pre = 0;
    for (unsigned bit = 0; bit < 24; bit++)
        cols[bit & 3] |= (uint8_t)(((v >> bit) & 1) << (bit >> 2));
    for (unsigned c = 0; c < 4; c++)
        cols[c] = s6(cols[c]);
    for (unsigned bit = 0; bit < 24; bit++)
        pre |= (uint32_t)(((cols[bit & 3] >> (bit >> 2)) & 1) << bit);
    return s24_linear(pre);
}

int main(void) {
    const uint32_t n = 1u << 24;
    uint8_t *seen = calloc(n, 1);
    if (!seen) return 2;

    uint64_t fixed = 0;
    uint32_t *hist = calloc(n + 1, sizeof(uint32_t));
    if (!hist) return 2;
    for (uint32_t x = 0; x < n; x++) {
        if (s24(x) == x) fixed++;
        if (!seen[x]) {
            uint32_t len = 0, y = x;
            while (!seen[y]) {
                seen[y] = 1;
                y = s24(y);
                len++;
            }
            hist[len]++;
        }
    }

    const uint32_t dx = column_vector(1, 32, 16, 42);
    const uint32_t dy = s24_linear(column_vector(17, 40, 20, 1));
    uint64_t witnesses = 0;
    for (uint32_t x = 0; x < n; x++)
        witnesses += (s24(x) ^ s24(x ^ dx)) == dy;

    printf("{\n");
    printf("  \"universe_size\": %u,\n", n);
    printf("  \"fixed_points\": %llu,\n", (unsigned long long)fixed);
    printf("  \"cycle_length_histogram\": {");
    int first = 1;
    for (uint32_t len = 1; len <= n; len++) {
        if (!hist[len]) continue;
        printf("%s\"%u\":%u", first ? "" : ",", len, hist[len]);
        first = 0;
    }
    printf("},\n");
    printf("  \"selected_input_difference\": %u,\n", dx);
    printf("  \"selected_output_difference\": %u,\n", dy);
    printf("  \"selected_transition_witnesses\": %llu,\n",
           (unsigned long long)witnesses);
    printf("  \"s6_table\": [");
    for (unsigned x = 0; x < 64; x++)
        printf("%s%u", x ? "," : "", s6((uint8_t)x));
    printf("]\n");
    printf("}\n");
    free(hist);
    free(seen);
    return 0;
}
