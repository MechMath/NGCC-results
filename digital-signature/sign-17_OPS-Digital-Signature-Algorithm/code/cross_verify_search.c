#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "SIG_AlgorithmInstance.h"
#include "auxfunc.h"
#include "drng.h"
#include "packing.h"
#include "params.h"
#include "poly.h"
#include "polyvec.h"

DRNG_ctx drng_algorithm;

static void crh(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen)
{
    pseudohash((unsigned long long)outlen * 8ULL, in,
               (unsigned long long)inlen * 8ULL, out);
}

static int32_t spec_use_hint(int32_t a, unsigned h)
{
    const int32_t alpha = 2 * GAMMA2;
    const int32_t m = Q / alpha;
    int32_t a1 = (a + GAMMA2) / alpha;
    int32_t a0;

    if (a1 == m)
        a1 = 0;
    a0 = a - a1 * alpha;
    if (a0 > (Q - 1) / 2)
        a0 -= Q;
    if (h == 0)
        return a1;
    return a0 > 0 ? (a1 + 1) % m : (a1 + m - 1) % m;
}

static int spec_verify(const uint8_t *sig, const uint8_t *m, size_t mlen,
                       const uint8_t *pk, int report)
{
    uint8_t buf[K * POLYW1_PACKEDBYTES];
    uint8_t rho[SEEDBYTES], mu[CRHBYTES], tr[CRHBYTES];
    uint8_t c[CTILDEBYTES], c2[CTILDEBYTES];
    uint8_t ctmp[CRHBYTES + K * POLYW1_PACKEDBYTES];
    uint8_t pre[2] = {0, 0};
    uint8_t *tmp;
    poly cp;
    polyvecl mat[K], z;
    polyveck t1, w, h;

    unpack_pk(rho, &t1, pk);
    if (unpack_sig(c, &z, &h, sig))
        return -2;
    if (polyvecl_chknorm(&z, GAMMA1 - BETA))
        return -3;

    crh(tr, CRHBYTES, pk, CRYPTO_PUBLICKEYBYTES);
    tmp = malloc(CRHBYTES + sizeof(pre) + mlen);
    if (tmp == NULL)
        return -4;
    memcpy(tmp, tr, CRHBYTES);
    memcpy(tmp + CRHBYTES, pre, sizeof(pre));
    memcpy(tmp + CRHBYTES + sizeof(pre), m, mlen);
    crh(mu, CRHBYTES, tmp, CRHBYTES + sizeof(pre) + mlen);
    free(tmp);

    poly_challenge(&cp, c);
    polyvec_matrix_expand(mat, rho);
    polyvecl_ntt(&z);
    polyvec_matrix_pointwise_montgomery(&w, mat, &z);
    poly_ntt(&cp);
    polyveck_shiftl(&t1);
    polyveck_ntt(&t1);
    polyveck_pointwise_poly_montgomery(&t1, &cp, &t1);
    polyveck_sub(&w, &w, &t1);
    polyveck_reduce(&w);
    polyveck_invntt_tomont(&w);
    polyveck_caddq(&w);

    for (unsigned i = 0; i < K; ++i) {
        for (unsigned j = 0; j < N; ++j) {
            int32_t a = w.vec[i].coeffs[j];
            int32_t submitted =
                use_hint(a, (unsigned int)h.vec[i].coeffs[j]);
            int32_t specified =
                spec_use_hint(a, (unsigned int)h.vec[i].coeffs[j]);
            if (report && submitted != specified)
                printf("high_bit_difference i=%u j=%u a=%d hint=%d "
                       "submitted_high=%d specified_high=%d\n",
                       i, j, a, h.vec[i].coeffs[j], submitted, specified);
            w.vec[i].coeffs[j] = specified;
        }
    }
    polyveck_pack_w1(buf, &w);
    memcpy(ctmp, mu, CRHBYTES);
    memcpy(ctmp + CRHBYTES, buf, sizeof(buf));
    sm3hash((unsigned long long)CTILDEBYTES * 8ULL, ctmp,
            (unsigned long long)sizeof(ctmp) * 8ULL, c2);
    return memcmp(c, c2, CTILDEBYTES) == 0 ? 0 : -5;
}

int main(int argc, char **argv)
{
    uint8_t pk[CRYPTO_PUBLICKEYBYTES], sk[CRYPTO_SECRETKEYBYTES];
    uint8_t sig[CRYPTO_BYTES], msg[16] = {0};
    uint8_t seed[55];
    unsigned long long pklen = sizeof(pk), sklen = sizeof(sk), siglen;
    unsigned long max_trials = argc > 1 ? strtoul(argv[1], NULL, 10) : 20000;
    FILE *f;

    for (unsigned i = 0; i < sizeof(seed); ++i)
        seed[i] = (uint8_t)(0x5a ^ i);
    if (init_random_number(&drng_algorithm, seed, sizeof(seed)) != 0)
        return 2;
    if (sig_keygen(pk, &pklen, sk, &sklen) != 0)
        return 3;

    for (unsigned trial = 0; trial < max_trials; ++trial) {
        siglen = sizeof(sig);
        memcpy(msg, &trial, sizeof(trial));
        if (sig_sign(sk, sklen, msg, sizeof(msg), sig, &siglen) != 0)
            continue;
        if (sig_verify(pk, pklen, sig, siglen, msg, sizeof(msg)) != 0 ||
            spec_verify(sig, msg, sizeof(msg), pk, 0) == 0)
            continue;

        printf("found_trial=%u\n", trial);
        printf("submitted_verify=accept\nspec_verify=reject\n");
        spec_verify(sig, msg, sizeof(msg), pk, 1);
        f = fopen("witness.pk", "wb"); fwrite(pk, 1, pklen, f); fclose(f);
        f = fopen("witness.sig", "wb"); fwrite(sig, 1, siglen, f); fclose(f);
        f = fopen("witness.msg", "wb"); fwrite(msg, 1, sizeof(msg), f); fclose(f);
        return 0;
    }
    printf("not_found trials=%lu\n", max_trials);
    return 1;
}
