#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "types.h"

int32_t stock_predict(const int32_t features[11]);
int32_t l1json_predict(const int32_t features[11]);

enum { FEATURE_SCALE = 256 };

static uint32_t var_threshold_q(int level, uint32_t weight)
{
    uint32_t a;
    uint32_t b;
    if (level == 1) {
        a = 2842U;
        b = 1679028U;
    } else {
        a = 3950U;
        b = 968615U;
    }
    return a + (uint32_t)(((uint64_t)b * weight) >> 20);
}

static uint32_t lower_bound_q(int level, uint32_t initial, uint32_t iter)
{
    const uint32_t t0 = var_threshold_q(level, initial);
    const uint32_t min = ((level == 1 ? 71U : 137U) + 1U) * FEATURE_SCALE / 2U;
    const uint32_t margin = (level == 1 ? 3U : 6U) * FEATURE_SCALE;
    const uint32_t transition = (t0 - min) / 3U;
    if (iter == 1U) {
        return t0 + margin;
    }
    return t0 + margin - transition;
}

static uint32_t ceil_q(uint32_t x)
{
    return (x + FEATURE_SCALE - 1U) / FEATURE_SCALE;
}

static uint32_t clamp_threshold(int level, int32_t x)
{
    const uint32_t d = level == 1 ? 71U : 137U;
    const uint32_t lo = (d + 1U) / 2U;
    if (x < (int32_t)lo) {
        return lo;
    }
    if (x > (int32_t)d) {
        return d;
    }
    return (uint32_t)x;
}

static uint64_t rng_state = UINT64_C(0x9e3779b97f4a7c15);

static uint32_t rng_below(uint32_t n)
{
    rng_state ^= rng_state >> 12;
    rng_state ^= rng_state << 25;
    rng_state ^= rng_state >> 27;
    return (uint32_t)((rng_state * UINT64_C(2685821657736338717)) % n);
}

static void make_features(int32_t f[11], int level, uint32_t iter,
                          uint32_t initial, uint32_t prev, uint32_t current,
                          uint32_t z0, uint32_t z1)
{
    const uint32_t var_q = var_threshold_q(level, current);
    const uint32_t lower_q = lower_bound_q(level, initial, iter);
    const uint32_t var_t = ceil_q(var_q);
    const uint32_t lower_t = ceil_q(lower_q);
    const uint32_t base = clamp_threshold(level, (int32_t)(var_q > lower_q ? var_t : lower_t));
    const uint32_t delta_s = prev > current ? prev - current : 0U;
    const uint32_t vals[11] = {
        (uint32_t)level, iter, initial, prev, current, delta_s,
        z0, z1, var_t, lower_t, base
    };
    for (size_t i = 0; i < 11; i++) {
        f[i] = (int32_t)(vals[i] * FEATURE_SCALE);
    }
}

int main(int argc, char **argv)
{
    const uint64_t trials = argc > 1 ? strtoull(argv[1], NULL, 10) : 1000000ULL;
    uint64_t differences = 0;
    uint64_t printed = 0;
    const int levels[2] = {1, 5};
    const uint32_t maxt[2] = {12323U, 40973U};

    printf("trial,level,iteration,initial,prev,current,z0,z1,stock,l1json\n");
    for (uint64_t i = 0; i < trials; i++) {
        const int which = (int)(i & 1U);
        const int level = levels[which];
        const uint32_t max_weight = maxt[which];
        const uint32_t iter = 1U + rng_below(2U);
        uint32_t initial;
        uint32_t prev;
        uint32_t current;

        if (iter == 1U) {
            current = rng_below(max_weight + 1U);
            prev = current;
            initial = rng_below(max_weight + 1U);
        } else {
            current = rng_below(max_weight + 1U);
            prev = rng_below(max_weight + 1U);
            initial = rng_below(max_weight + 1U);
        }

        const uint32_t max_ones = current < prev ? current : prev;
        const uint32_t z0 = rng_below(max_ones + 1U);
        const uint32_t z1 = current - z0;

        int32_t f[11];
        make_features(f, level, iter, initial, prev, current, z0, z1);
        const int32_t stock = stock_predict(f);
        const int32_t supplied = l1json_predict(f);
        if (stock != supplied) {
            differences++;
            if (printed < 20000) {
                printf("%" PRIu64 ",%d,%u,%u,%u,%u,%u,%u,%" PRId32 ",%" PRId32 "\n",
                       i, level, iter, initial, prev, current, z0, z1,
                       stock, supplied);
                printed++;
            }
        }
    }
    fprintf(stderr, "trials=%" PRIu64 " differences=%" PRIu64 "\n",
            trials, differences);
    return differences == 0 ? 0 : 1;
}
