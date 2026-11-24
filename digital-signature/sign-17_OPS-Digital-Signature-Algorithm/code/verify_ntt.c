#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "params.h"
#include "ntt.h"
#include "reduce.h"

static int32_t norm_mod(int64_t x)
{
    x %= Q;
    if (x < 0) x += Q;
    return x > Q / 2 ? (int32_t)(x - Q) : (int32_t)x;
}

static uint64_t state = UINT64_C(0x9e3779b97f4a7c15);
static uint32_t next_u32(void)
{
    state ^= state << 7;
    state ^= state >> 9;
    state ^= state << 8;
    return (uint32_t)state;
}

int main(void)
{
    int32_t a[N], b[N], got[N], expect[N];
    int64_t acc[N];

    for (unsigned trial = 0; trial < 64; trial++) {
        for (unsigned i = 0; i < N; i++) {
            a[i] = norm_mod(next_u32());
            b[i] = norm_mod(next_u32());
        }

        memcpy(got, a, sizeof(got));
        ntt(got);
        invntt_tomont(got);
        for (unsigned i = 0; i < N; i++) {
            got[i] = norm_mod(montgomery_reduce((int64_t)got[i]));
            if (got[i] != norm_mod(a[i])) {
                printf("roundtrip mismatch trial=%u index=%u got=%d want=%d\n",
                       trial, i, got[i], norm_mod(a[i]));
                return 1;
            }
        }

        memset(acc, 0, sizeof(acc));
        for (unsigned i = 0; i < N; i++) {
            for (unsigned j = 0; j < N; j++) {
                int64_t p = (int64_t)a[i] * b[j];
                if (i + j < N) acc[i + j] += p;
                else acc[i + j - N] -= p;
            }
        }
        for (unsigned i = 0; i < N; i++)
            expect[i] = norm_mod(acc[i]);

        ntt(got);
        int32_t bt[N];
        memcpy(bt, b, sizeof(bt));
        ntt(bt);
        for (unsigned i = 0; i < N; i++)
            got[i] = montgomery_reduce((int64_t)got[i] * bt[i]);
        invntt_tomont(got);
        for (unsigned i = 0; i < N; i++) {
            got[i] = norm_mod(got[i]);
            if (got[i] != expect[i]) {
                printf("multiply mismatch trial=%u index=%u got=%d want=%d\n",
                       trial, i, got[i], expect[i]);
                return 1;
            }
        }
    }

    printf("PASS N=%u trials=64 roundtrip=full multiply=negacyclic-full\n", N);
    return 0;
}
