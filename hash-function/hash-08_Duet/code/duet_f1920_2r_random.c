// Deterministic exploratory search for a small f-1920 two-S-layer
// active-support trail. This can find an upper witness but cannot prove
// a lower bound.
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static const uint32_t M30_FIRST =
    (1u << 0) | (1u << 3) | (1u << 10) | (1u << 13) | (1u << 14) |
    (1u << 15) | (1u << 16) | (1u << 18) | (1u << 21) | (1u << 26) |
    (1u << 28);

static uint64_t rng_state = 0x243f6a8885a308d3ULL;

static uint64_t next_rand(void) {
    uint64_t x = rng_state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    rng_state = x;
    return x;
}

static void linear(const uint64_t in[30], uint64_t out[30]) {
    uint64_t ms[30] = {0};
    for (unsigned i = 0; i < 30; ++i) {
        for (unsigned j = 0; j < 30; ++j) {
            if ((M30_FIRST >> ((j + 30 - i) % 30)) & 1u) {
                ms[i] ^= in[j];
            }
        }
    }
    for (unsigned t = 0; t < 30; ++t) {
        uint64_t x = ms[t];
        out[t] = (x << t) | (x >> ((64 - t) & 63));
        unsigned a = (t + 21) & 63;
        out[t] ^= (x << a) | (x >> ((64 - a) & 63));
        unsigned b = (t + 43) & 63;
        out[t] ^= (x << b) | (x >> ((64 - b) & 63));
    }
}

static unsigned active_cells(const uint64_t state[30]) {
    unsigned active = 0;
    for (unsigned j = 0; j < 6; ++j) {
        for (unsigned k = 0; k < 64; ++k) {
            uint64_t cell = 0;
            for (unsigned i = 0; i < 5; ++i) {
                cell |= ((state[j * 5 + i] >> k) & 1u) << i;
            }
            active += cell != 0;
        }
    }
    return active;
}

int main(void) {
    unsigned best = 999;
    uint64_t best_in[30] = {0}, best_out[30] = {0};
    for (uint64_t trial = 0; trial < 200000000; ++trial) {
        uint64_t in[30] = {0}, out[30];
        unsigned s1 = 1 + (unsigned)(next_rand() % 7);
        for (unsigned a = 0; a < s1; ++a) {
            unsigned cell = (unsigned)(next_rand() % 384);
            unsigned j = cell / 64;
            unsigned k = cell % 64;
            unsigned value = 1 + (unsigned)(next_rand() % 31);
            for (unsigned i = 0; i < 5; ++i) {
                if ((value >> i) & 1u) {
                    in[j * 5 + i] |= 1ULL << k;
                }
            }
        }
        linear(in, out);
        unsigned total = active_cells(in) + active_cells(out);
        if (total < best) {
            best = total;
            memcpy(best_in, in, sizeof(in));
            memcpy(best_out, out, sizeof(out));
            fprintf(stderr, "trial=%llu best=%u\n",
                    (unsigned long long)trial, best);
        }
        if (total <= 7) {
            printf("FOUND total=%u trial=%llu\n",
                   total, (unsigned long long)trial);
            for (unsigned t = 0; t < 30; ++t) {
                printf("%02u %016llx %016llx\n", t,
                       (unsigned long long)in[t],
                       (unsigned long long)out[t]);
            }
            return 0;
        }
    }
    printf("NO_WITNESS best=%u trials=200000000 seed=%016llx\n",
           best, (unsigned long long)0x243f6a8885a308d3ULL);
    return 0;
}
