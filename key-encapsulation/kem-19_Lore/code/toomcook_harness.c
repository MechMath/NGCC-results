#include "toomcook.h"

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static uint64_t state = UINT64_C(0x9321cf3597def00c);

static uint32_t next_u32(void) {
    state ^= state << 13;
    state ^= state >> 7;
    state ^= state << 17;
    return (uint32_t)(state >> 16);
}

static uint64_t digest(const int16_t x[LORE_N]) {
    uint64_t h = UINT64_C(1469598103934665603);
    for (int i = 0; i < LORE_N; ++i) {
        uint16_t v = (uint16_t)x[i];
        h ^= (uint8_t)v;
        h *= UINT64_C(1099511628211);
        h ^= (uint8_t)(v >> 8);
        h *= UINT64_C(1099511628211);
    }
    return h;
}

static int check_case(const int16_t a[LORE_N], const int16_t b[LORE_N],
                      uint64_t case_id) {
    int16_t actual[LORE_N] = {0};
    int16_t expected[LORE_N] = {0};
    poly_mul_acc(a, b, actual);

    /*
     * These test inputs are in the implementation's actual range:
     * a is in {-1,0,1,2}; b is in {-2,-1,0,1,2}. Their full convolution
     * coefficients are far below INT16_MAX, so reduction modulo X^N+1 is
     * an ordinary signed convolution followed by c[i]-c[i+N].
     */
    int16_t c[2 * LORE_N] = {0};
    for (int i = 0; i < LORE_N; ++i) {
        for (int j = 0; j < LORE_N; ++j) {
            c[i + j] = (int16_t)(c[i + j] + a[i] * b[j]);
        }
    }
    for (int i = 0; i < LORE_N; ++i) {
        expected[i] = (int16_t)(c[i] - c[i + LORE_N]);
    }

    if (memcmp(actual, expected, sizeof(actual)) != 0) {
        fprintf(stderr, "MISMATCH level=%d case=%" PRIu64 "\n",
                LORE_LEVEL, case_id);
        for (int i = 0; i < LORE_N; ++i) {
            if (actual[i] != expected[i]) {
                fprintf(stderr, "first_index=%d actual=%d expected=%d\n",
                        i, actual[i], expected[i]);
                return 1;
            }
        }
    }
    return 0;
}

int main(void) {
    static const int16_t a_values[] = {-1, 0, 1, 2};
    static const int16_t b_values[] = {-2, -1, 0, 1, 2};
    int16_t a[LORE_N];
    int16_t b[LORE_N];
    uint64_t aggregate = UINT64_C(1469598103934665603);

    for (uint64_t t = 0; t < 100; ++t) {
        for (int i = 0; i < LORE_N; ++i) {
            a[i] = a_values[next_u32() % 4];
            b[i] = b_values[next_u32() % 5];
        }
        if (check_case(a, b, t) != 0) {
            return 1;
        }
        uint64_t d = digest(a) ^ (digest(b) << 1);
        aggregate ^= d;
        aggregate *= UINT64_C(1099511628211);
    }

    printf("PASS level=%d cases=100 digest=%016" PRIx64 "\n",
           LORE_LEVEL, aggregate);
    return 0;
}
