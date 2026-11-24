#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include "params.h"
#include "poly.h"
#include "polyvec.h"
#include "mult.h"

static uint64_t state;
static uint32_t next_u32(void)
{
    state ^= state << 7;
    state ^= state >> 9;
    state ^= state << 8;
    return (uint32_t)state;
}

static int32_t small( void )
{
    return (int32_t)(next_u32() % (2u * ETA + 1u)) - ETA;
}

static int32_t t0_small( void )
{
    return (int32_t)(next_u32() % 8192u) - 4095;
}

static int32_t ring(const poly *c, const poly *v, unsigned k)
{
    int32_t r = 0;
    for (unsigned i = 0; i < N; i++) {
        unsigned j = (k + N - i) % N;
        if (i <= k) r += c->coeffs[i] * v->coeffs[j];
        else r -= c->coeffs[i] * v->coeffs[j];
    }
    return r;
}

int main(void)
{
    poly c;
    polyvecl s1, y, z;
    polyveck s2, t0, w0, w0p, h;
#if TAU == 39
    uint32_t s1tab[2*N], s2tab[2*N];
#else
    uint64_t s1tab[2*N], s2tab[2*N];
#endif
    uint64_t t0lo[2*N], t0hi[2*N];

    for (unsigned trial = 0; trial < 128; trial++) {
        state = UINT64_C(0xd1b54a32d192ed03) ^ (UINT64_C(128) * trial + 17);
        memset(&c, 0, sizeof(c));
        for (unsigned n = 0; n < TAU; n++) {
            unsigned p;
            do p = next_u32() % N; while (c.coeffs[p] != 0);
            c.coeffs[p] = (next_u32() & 1) ? 1 : -1;
        }
        for (unsigned j = 0; j < L; j++)
            for (unsigned k = 0; k < N; k++) {
                s1.vec[j].coeffs[k] = small();
                y.vec[j].coeffs[k] = small();
            }
        for (unsigned j = 0; j < K; j++)
            for (unsigned k = 0; k < N; k++) {
                s2.vec[j].coeffs[k] = small();
                t0.vec[j].coeffs[k] = t0_small();
                w0.vec[j].coeffs[k] = (int32_t)(next_u32() % 2000001u) - 1000000;
            }

#if N == 1024
        prepare_s1_table_ops512(s1tab, &s1);
        prepare_s2_table_ops512(s2tab, &s2);
        prepare_t0_table_ops512(t0lo, t0hi, &t0);
        if (evaluate_cs1_cs2_early_check_ops512(&z, &w0p, &c, s1tab, s2tab,
                                                &y, &w0, INT32_MAX, INT32_MAX))
            return 2;
        evaluate_ct0_ops512(&h, &c, t0lo, t0hi);
#elif TAU == 45
        prepare_s1_table_ops256(s1tab, &s1);
        prepare_s2_table_ops256(s2tab, &s2);
        prepare_t0_table_ops256(t0lo, t0hi, &t0);
        if (evaluate_cs1_cs2_early_check_ops256(&z, &w0p, &c, s1tab, s2tab,
                                                &y, &w0, INT32_MAX, INT32_MAX))
            return 2;
        evaluate_ct0_ops256(&h, &c, t0lo, t0hi);
#else
        prepare_s1_table_ops128(s1tab, &s1);
        prepare_s2_table_ops128(s2tab, &s2);
        prepare_t0_table_ops128(t0lo, &t0);
        if (evaluate_cs1_cs2_early_check_ops128(&z, &w0p, &c, s1tab, s2tab,
                                                &y, &w0, INT32_MAX, INT32_MAX))
            return 2;
        evaluate_ct0_ops128(&h, &c, t0lo);
#endif

        for (unsigned j = 0; j < L; j++)
            for (unsigned k = 0; k < N; k++) {
                int32_t want = y.vec[j].coeffs[k] + ring(&c, &s1.vec[j], k);
                if (z.vec[j].coeffs[k] != want) {
                    printf("s1 mismatch trial=%u lane=%u k=%u\n", trial, j, k);
                    return 1;
                }
            }
        for (unsigned j = 0; j < K; j++)
            for (unsigned k = 0; k < N; k++) {
                int32_t wantw = w0.vec[j].coeffs[k] - ring(&c, &s2.vec[j], k);
                int32_t wantt = ring(&c, &t0.vec[j], k);
                if (w0p.vec[j].coeffs[k] != wantw || h.vec[j].coeffs[k] != wantt) {
                    printf("s2/t0 mismatch trial=%u lane=%u k=%u\n", trial, j, k);
                    return 1;
                }
            }
    }
    printf("PASS N=%u TAU=%u trials=128 all packed identities exact\n", N, TAU);
    return 0;
}
