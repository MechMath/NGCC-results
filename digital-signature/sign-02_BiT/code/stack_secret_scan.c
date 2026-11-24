#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "SIG_AlgorithmInstance.h"
#include "drng.h"
#include "params.h"
#include "packing.h"
#include "polyvec.h"

DRNG_ctx drng_algorithm;

static unsigned count_matches(const unsigned char *lo, const unsigned char *hi,
                              const unsigned char *needle, size_t len) {
    unsigned count = 0;
    for (const unsigned char *p = lo; p + len <= hi; ++p)
        if (memcmp(p, needle, len) == 0) ++count;
    return count;
}

int main(void) {
    static unsigned char seed[55], msg[32];
    static unsigned char pk[BIT_PUBLICKEYBYTES], sk[BIT_SECRETKEYBYTES];
    static unsigned char sig[BIT_SIGNBYTES];
    static unsigned char seed_A[BIT_SEEDBYTES], secret_seed[BIT_SEEDBYTES], tr[BIT_TRBYTES];
    static polyveck b1, e, b0;
    static polyvecl s0;
    unsigned long long pk_len, sk_len, sig_len;
    for (unsigned i = 0; i < sizeof(seed); ++i) seed[i] = (unsigned char)(i + 1);
    if (init_random_number(&drng_algorithm, seed, sizeof(seed)) != 0) return 2;
    if (sig_keygen(pk, &pk_len, sk, &sk_len) != 0) return 3;
    if (sig_sign(sk, sk_len, msg, sizeof(msg), sig, &sig_len) != 0) return 4;
    unpack_sk(seed_A, &b1, secret_seed, tr, &s0, &e, &b0, sk);
    memset(sk, 0, sizeof(sk));

    volatile unsigned char marker;
    const unsigned char *lo = (const unsigned char *)&marker - 262144;
    const unsigned char *hi = (const unsigned char *)&marker;
    unsigned seed_matches = count_matches(lo, hi, secret_seed, sizeof(secret_seed));
    unsigned s0_matches = count_matches(lo, hi, (const unsigned char *)&s0.vec[0].coeffs[0],
                                        sizeof(s0.vec[0].coeffs[0]) * 16);
    unsigned e_matches = count_matches(lo, hi, (const unsigned char *)&e.vec[0].coeffs[0],
                                       sizeof(e.vec[0].coeffs[0]) * 16);
    printf("secret_seed=%u s0_16coeff=%u e_16coeff=%u\n",
           seed_matches, s0_matches, e_matches);
    return 0;
}
