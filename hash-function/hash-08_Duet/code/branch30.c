// Exhaustive GF(2) branch-number check for the Duet f-1920 M30 matrix.
// The matrix is the right-circulant matrix described on spec page 10,
// with the first row below. Gray-code enumeration visits all 2^30 inputs.
#include <stdint.h>
#include <stdio.h>

static const uint32_t v =
    (1u << 0) | (1u << 3) | (1u << 10) | (1u << 13) | (1u << 14) |
    (1u << 15) | (1u << 16) | (1u << 18) | (1u << 21) | (1u << 26) |
    (1u << 28);

int main(void) {
    uint32_t columns[30];
    for (unsigned c = 0; c < 30; ++c) {
        uint32_t col = 0;
        for (unsigned r = 0; r < 30; ++r) {
            // Row r has first-row coordinate c-r modulo 30.
            if ((v >> ((c + 30 - r) % 30)) & 1u) col |= 1u << r;
        }
        columns[c] = col;
    }

    uint32_t x = 0, y = 0, previous_gray = 0;
    unsigned best = 31;
    uint32_t best_x = 0, best_y = 0;
    unsigned best_block = 13;
    uint32_t best_block_x = 0, best_block_y = 0;
    const uint32_t five_bits = 31u;
    const uint32_t stop = 1u << 30;
    for (uint32_t i = 1; i < stop; ++i) {
        uint32_t gray = i ^ (i >> 1);
        uint32_t changed = gray ^ previous_gray;
        unsigned bit = (unsigned)__builtin_ctz(changed);
        x ^= 1u << bit;
        y ^= columns[bit];
        unsigned weight = (unsigned)__builtin_popcount(x) +
                          (unsigned)__builtin_popcount(y);
        if (weight < best) {
            best = weight;
            best_x = x;
            best_y = y;
        }
        unsigned x_blocks = (!!(x & five_bits)) +
                            (!!(x & (five_bits << 5))) +
                            (!!(x & (five_bits << 10))) +
                            (!!(x & (five_bits << 15))) +
                            (!!(x & (five_bits << 20))) +
                            (!!(x & (five_bits << 25)));
        unsigned y_blocks = (!!(y & five_bits)) +
                            (!!(y & (five_bits << 5))) +
                            (!!(y & (five_bits << 10))) +
                            (!!(y & (five_bits << 15))) +
                            (!!(y & (five_bits << 20))) +
                            (!!(y & (five_bits << 25)));
        if (x_blocks + y_blocks < best_block) {
            best_block = x_blocks + y_blocks;
            best_block_x = x;
            best_block_y = y;
        }
        previous_gray = gray;
    }
    printf("rank_checked_inputs=%u\n", stop - 1);
    printf("branch_number=%u\n", best);
    printf("witness_x=%08x\n", best_x);
    printf("witness_y=%08x\n", best_y);
    printf("witness_weight_x=%u\n", (unsigned)__builtin_popcount(best_x));
    printf("witness_weight_y=%u\n", (unsigned)__builtin_popcount(best_y));
    printf("five_bit_block_branch_number=%u\n", best_block);
    printf("block_witness_x=%08x\n", best_block_x);
    printf("block_witness_y=%08x\n", best_block_y);
    return 0;
}
