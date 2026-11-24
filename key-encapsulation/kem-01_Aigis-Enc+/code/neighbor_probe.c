#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "api.h"
#include "params.h"
#include "poly.h"
#include "pack.h"
#include "owcpa.h"

static int same_bytes(const unsigned char *a, const unsigned char *b, size_t n)
{
    return memcmp(a, b, n) == 0;
}

int main(int argc, char **argv)
{
    int trials = argc > 1 ? atoi(argv[1]) : 100;
    unsigned char pk[PK_BYTES], sk[SK_BYTES];
    unsigned char ct[CT_BYTES], ss[SEED_BYTES];
    unsigned char ct_lo[CT_BYTES], ct_hi[CT_BYTES];
    unsigned char m[SEED_BYTES], m_lo[SEED_BYTES], m_hi[SEED_BYTES];
    unsigned char ss_lo[SEED_BYTES], ss_hi[SEED_BYTES];
    int correct = 0, lo_preserved = 0, hi_preserved = 0, either_preserved = 0;
    int lo_key = 0, hi_key = 0, either_key = 0;

#if defined(PARAMS) && PARAMS == 2
    const int affected = PARAM_N - 3;
    const int step = 417;
#else
    const int affected = PARAM_N - 2;
    const int step = 209;
#endif

    for (int trial = 0; trial < trials; ++trial) {
        poly u, v;
        if (mkem_keygen(pk, sk) != 0 || mkem_enc(pk, ss, ct) != 0) {
            fprintf(stderr, "keygen/enc failed at trial %d\n", trial);
            return 2;
        }
        owcpa_dec(m, ct, sk);

        unpack_ciphertext(&u, &v, ct);

        int old = v.coeffs[affected];
        v.coeffs[affected] = (old + step) % PARAM_Q;
        pack_ciphertext(ct_hi, &u, &v);
        v.coeffs[affected] = (old - step + PARAM_Q) % PARAM_Q;
        pack_ciphertext(ct_lo, &u, &v);

        if (same_bytes(ct_lo, ct, CT_BYTES) || same_bytes(ct_hi, ct, CT_BYTES)) {
            fprintf(stderr, "neighbor construction collided at trial %d\n", trial);
            return 4;
        }

        if (mkem_dec(sk, ct_lo, ss_lo) != 0 ||
            mkem_dec(sk, ct_hi, ss_hi) != 0) {
            fprintf(stderr, "tampered dec failed at trial %d\n", trial);
            return 5;
        }
        owcpa_dec(m_lo, ct_lo, sk);
        owcpa_dec(m_hi, ct_hi, sk);

        correct += 1;
        lo_preserved += same_bytes(m_lo, m, SEED_BYTES);
        hi_preserved += same_bytes(m_hi, m, SEED_BYTES);
        either_preserved += same_bytes(m_lo, m, SEED_BYTES) ||
                            same_bytes(m_hi, m, SEED_BYTES);
        lo_key += same_bytes(ss_lo, ss, SEED_BYTES);
        hi_key += same_bytes(ss_hi, ss, SEED_BYTES);
        either_key += same_bytes(ss_lo, ss, SEED_BYTES) ||
                      same_bytes(ss_hi, ss, SEED_BYTES);
    }

    printf("params=%d trials=%d affected=%d step=%d correct=1 lo_preserved=%d "
           "hi_preserved=%d either_preserved=%d lo_key=%d hi_key=%d either_key=%d\n",
           PARAMS, trials, affected, step, lo_preserved, hi_preserved,
           either_preserved, lo_key, hi_key, either_key);
    return either_key == trials ? 0 : 1;
}
