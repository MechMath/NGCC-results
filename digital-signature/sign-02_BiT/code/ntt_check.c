#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "params.h"
#include "ntt.h"
#include "reduce.h"

static int16_t centered(int32_t x)
{
    x %= BIT_Q;
    if (x < 0) x += BIT_Q;
    if (x > BIT_Q / 2) x -= BIT_Q;
    return (int16_t)x;
}

static void naive_negacyclic(int16_t out[BIT_N],
                             const int16_t a[BIT_N],
                             const int16_t b[BIT_N])
{
    int64_t acc[BIT_N] = {0};
    for (int i = 0; i < BIT_N; ++i) {
        for (int j = 0; j < BIT_N; ++j) {
            int k = i + j;
            int sign = 1;
            if (k >= BIT_N) {
                k -= BIT_N;
                sign = -1;
            }
            acc[k] += sign * (int64_t)a[i] * (int64_t)b[j];
        }
    }
    for (int i = 0; i < BIT_N; ++i)
        out[i] = centered((int32_t)(acc[i] % BIT_Q));
}

static uint32_t next_u32(uint32_t *s)
{
    *s ^= *s << 13;
    *s ^= *s >> 17;
    *s ^= *s << 5;
    return *s;
}

int main(void)
{
    uint32_t s = 0x12345678U;
    int16_t a[BIT_N], b[BIT_N], want[BIT_N], got[BIT_N];
    int16_t ant[BIT_N], bnt[BIT_N], pnt[BIT_N];

    for (int i = 0; i < BIT_N; ++i) {
        a[i] = (int16_t)((int32_t)(next_u32(&s) % BIT_Q) - BIT_Q / 2);
        b[i] = (int16_t)((int32_t)(next_u32(&s) % BIT_Q) - BIT_Q / 2);
    }

    naive_negacyclic(want, a, b);
    for (int i = 0; i < BIT_N; ++i) {
        ant[i] = (int16_t)reduce_to_unsigned(a[i]);
        bnt[i] = (int16_t)reduce_to_unsigned(b[i]);
    }
    ntt_forward(ant);
    ntt_forward(bnt);
    ntt_basemul_raw(pnt, ant, bnt);
    ntt_montgomery_lift(pnt);
    ntt_inverse(pnt);
    for (int i = 0; i < BIT_N; ++i)
        got[i] = reduce_to_signed((uint16_t)pnt[i]);

    int mismatches = 0;
    for (int i = 0; i < BIT_N; ++i) {
        if (got[i] != want[i]) {
            if (mismatches < 8)
                printf("mismatch %d: got=%d want=%d\n", i, got[i], want[i]);
            ++mismatches;
        }
    }
    printf("mismatches=%d\n", mismatches);
    return mismatches == 0 ? 0 : 1;
}
