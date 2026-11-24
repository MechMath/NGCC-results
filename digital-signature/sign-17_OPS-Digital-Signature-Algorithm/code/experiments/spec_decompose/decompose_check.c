#include <stdint.h>
#include <stdio.h>

#define Q 67104769

/*
 * Submitted implementation formula from rounding.c.  The mode selects the
 * GAMMA2 value used by OPSsig-128, OPSsig-256, or OPSsig-512.
 */
static int32_t submitted_decompose(int32_t *a0, int32_t a, int32_t gamma2,
                                   int mode)
{
    int32_t a1;

    if (mode == 0) {
        a1 = ((((int64_t)a + 2097023) >> 8) * 524321) >> 33;
        a1 &= 15;
    } else if (mode == 1) {
        a1 = ((((int64_t)a + 699007) >> 8) * 786481) >> 32;
        a1 ^= ((47 - a1) >> 31) & a1;
    } else {
        a1 = ((((int64_t)a + 1398015) >> 9) * 393241) >> 31;
        a1 ^= ((23 - a1) >> 31) & a1;
    }

    *a0 = a - a1 * 2 * gamma2;
    *a0 -= (((Q - 1) / 2 - *a0) >> 31) & Q;
    return a1;
}

/* Algorithm 30 of the original OPS-SIG specification. */
static int32_t specified_decompose(int32_t *a0, int32_t a, int32_t gamma2)
{
    const int32_t alpha = 2 * gamma2;
    int32_t a1 = (a + gamma2) / alpha;

    if (a1 == Q / alpha)
        a1 = 0;
    *a0 = a - a1 * alpha;
    if (*a0 > (Q - 1) / 2)
        *a0 -= Q;
    return a1;
}

int main(void)
{
    const int32_t gamma2[3] = {
        (Q - 1) / 32,
        (Q - 1) / 96,
        (Q - 1) / 48
    };
    const char *name[3] = {"OPSsig-128", "OPSsig-256", "OPSsig-512"};
    long mismatches[3] = {0, 0, 0};

    for (int mode = 0; mode < 3; ++mode) {
        for (int32_t a = 0; a < Q; ++a) {
            int32_t submitted_a0;
            int32_t specified_a0;
            const int32_t submitted_a1 =
                submitted_decompose(&submitted_a0, a, gamma2[mode], mode);
            const int32_t specified_a1 =
                specified_decompose(&specified_a0, a, gamma2[mode]);

            if (submitted_a1 != specified_a1 ||
                submitted_a0 != specified_a0) {
                if (mismatches[mode] < 3)
                    printf("%s mismatch a=%d submitted=(%d,%d) "
                           "specified=(%d,%d)\n",
                           name[mode], a, submitted_a1, submitted_a0,
                           specified_a1, specified_a0);
                ++mismatches[mode];
            }
        }
    }

    printf("mismatch_counts OPSsig-128=%ld OPSsig-256=%ld "
           "OPSsig-512=%ld\n",
           mismatches[0], mismatches[1], mismatches[2]);
    return (mismatches[0] || mismatches[1] || mismatches[2]) ? 1 : 0;
}
