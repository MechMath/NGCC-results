#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "params.h"
#include "drng.h"
#include "packing.h"
#include "polyvec.h"
#include "sign.h"
#include "symmetric.h"

DRNG_ctx drng_algorithm;

#define SCAN_BYTES (256u * 1024u)

static uint64_t fnv1a64(const unsigned char *p, size_t n)
{
    uint64_t h = UINT64_C(1469598103934665603);
    for (size_t i = 0; i < n; i++) {
        h ^= p[i];
        h *= UINT64_C(1099511628211);
    }
    return h;
}

static void print_hex(const char *label, const unsigned char *p, size_t n)
{
    printf("%s", label);
    for (size_t i = 0; i < n; i++) printf("%02x", p[i]);
    putchar('\n');
}

int main(void)
{
    unsigned char pk[BIT_PUBLICKEYBYTES];
    unsigned char sk[BIT_SECRETKEYBYTES];
    unsigned char *oracle_sk = malloc(sizeof sk);
    unsigned char sig[BIT_SIGNBYTES];
    unsigned char sig2[BIT_SIGNBYTES];
    unsigned long long pklen = sizeof pk, sklen = sizeof sk;
    unsigned long long siglen = sizeof sig, sig2len = sizeof sig2;
    const unsigned char msg[] = "stack-recovery-independent-check";
    const unsigned char msg2[] = "forgery-after-stack-secret-recovery";
    unsigned char nonce[64];

    if (oracle_sk == NULL) return 2;
    memset(nonce, 0x5a, sizeof nonce);
    if (init_random_number(&drng_algorithm, nonce, sizeof nonce) != 0) return 3;
    if (bit_sig_keygen(pk, &pklen, sk, &sklen) != 0) return 4;
    if (pklen != BIT_PUBLICKEYBYTES || sklen != BIT_SECRETKEYBYTES) return 5;
    memcpy(oracle_sk, sk, sizeof sk);

    if (bit_sig_sign(sk, sklen, msg, sizeof msg - 1, sig, &siglen) != 0) return 6;

    /* The caller destroys its long-lived exported secret-key object. */
    memset(sk, 0, sizeof sk);

    {
        volatile unsigned char marker = 0;
        const uintptr_t end = (uintptr_t)&marker;
        const uintptr_t begin = end - SCAN_BYTES;
        const unsigned char *expected = oracle_sk + BIT_SEEDBYTES
                                         + BIT_POLYVECK_B1_BYTES;
        size_t matches = 0;
        uintptr_t first = 0;
        unsigned char leaked_seed[BIT_SEEDBYTES];

        for (uintptr_t a = begin; a + BIT_SEEDBYTES <= end; a++) {
            const unsigned char *p = (const unsigned char *)a;
            if (memcmp(p, expected, BIT_SEEDBYTES) == 0) {
                if (matches == 0) {
                    first = a;
                    memcpy(leaked_seed, p, sizeof leaked_seed);
                }
                matches++;
            }
        }

        printf("scan_bytes=%u matches=%zu marker=%" PRIuPTR
               " begin=%" PRIuPTR " end=%" PRIuPTR "\n",
               SCAN_BYTES, matches, end, begin, end);
        printf("first_match_offset_below_marker=%" PRIuPTR "\n", end - first);
        printf("sk_after_wipe_fnv1a64=%016" PRIx64 "\n",
               fnv1a64(sk, sizeof sk));
        if (matches == 0) return 8;

        printf("original_signature_verify=%s\n",
               bit_sig_verify(sig, siglen, msg, sizeof msg - 1,
                              pk, pklen) == 0 ? "true" : "false");
        if (bit_sig_verify(sig, siglen, msg, sizeof msg - 1,
                           pk, pklen) != 0) return 7;

        print_hex("leaked_secret_seed=", leaked_seed, sizeof leaked_seed);

        unsigned char seed_A[BIT_SEEDBYTES];
        unsigned char tr[BIT_TRBYTES];
        unsigned char recon_sk[BIT_SECRETKEYBYTES];
        poly_matrix_ntt A0_ntt;
        polyvecl s0;
        polyvecl_ntt s0_ntt;
        polyveck e, b, b1, b0;
        uint16_t sample_nonce = 0;

        unpack_pk(seed_A, &b1, pk);
#ifdef BIT_AVX2_RECOVERY
        polyvec_sample_S1_avx(&s0, &e, leaked_seed, &sample_nonce);
#else
        polyvecl_sample_S1(&s0, leaked_seed, &sample_nonce);
        polyveck_sample_S1(&e, leaked_seed, &sample_nonce);
#endif
        poly_matrix_expand_ntt(&A0_ntt, seed_A);
        polyvecl_to_ntt(&s0_ntt, &s0);
        poly_matrix_mul_vector_ntt(&b, &A0_ntt, &s0_ntt);
        polyveck_add_eta1(&b, &b, &e);
        polyveck_decompose_b(&b1, &b0, &b);
        bit_h256(tr, pk, BIT_PUBLICKEYBYTES);
        pack_sk(recon_sk, seed_A, &b1, leaked_seed, tr, &s0, &e, &b0);

        printf("reconstructed_pk_b1_sha256_placeholder=%016" PRIx64 "\n",
               fnv1a64((const unsigned char *)&b1, sizeof b1));
        printf("reconstructed_s0_e_b0_fnv1a64=%016" PRIx64 "\n",
               fnv1a64((const unsigned char *)&s0, sizeof s0)
               ^ fnv1a64((const unsigned char *)&e, sizeof e)
               ^ fnv1a64((const unsigned char *)&b0, sizeof b0));
        printf("packed_sk_equal=%s\n",
               memcmp(recon_sk, oracle_sk, sizeof recon_sk) == 0 ? "true" : "false");
        {
            unsigned char oseed_A[BIT_SEEDBYTES], oseed[BIT_SEEDBYTES], otr[BIT_TRBYTES];
            polyveck ob1, oe, ob0;
            polyvecl os0;
            unpack_sk(oseed_A, &ob1, oseed, otr, &os0, &oe, &ob0, oracle_sk);
            printf("component_equal seed_A=%d b1=%d seed=%d tr=%d s0=%d e=%d b0=%d\n",
                   memcmp(seed_A, oseed_A, sizeof seed_A) == 0,
                   memcmp(&b1, &ob1, sizeof b1) == 0,
                   memcmp(leaked_seed, oseed, sizeof leaked_seed) == 0,
                   memcmp(tr, otr, sizeof tr) == 0,
                   memcmp(&s0, &os0, sizeof s0) == 0,
                   memcmp(&e, &oe, sizeof e) == 0,
                   memcmp(&b0, &ob0, sizeof b0) == 0);
            for (size_t i = 0; i < sizeof recon_sk; i++) {
                if (recon_sk[i] != oracle_sk[i]) {
                    printf("first_sk_diff=%zu recon=%02x oracle=%02x\n",
                           i, recon_sk[i], oracle_sk[i]);
                    break;
                }
            }
        }
        if (memcmp(recon_sk, oracle_sk, sizeof recon_sk) != 0) return 9;

        if (bit_sig_sign(recon_sk, sizeof recon_sk, msg2,
                         sizeof msg2 - 1, sig2, &sig2len) != 0) return 10;
        printf("recovered_key_new_signature_verify=%s\n",
               bit_sig_verify(sig2, sig2len, msg2, sizeof msg2 - 1,
                              pk, pklen) == 0 ? "true" : "false");
        if (bit_sig_verify(sig2, sig2len, msg2, sizeof msg2 - 1,
                           pk, pklen) != 0) return 11;

        unsigned char unrelated[BIT_SEEDBYTES];
        memset(unrelated, 0xa7, sizeof unrelated);
        size_t unrelated_matches = 0;
        for (uintptr_t a = begin; a + BIT_SEEDBYTES <= end; a++) {
            if (memcmp((const unsigned char *)a, unrelated,
                       sizeof unrelated) == 0) unrelated_matches++;
        }
        printf("unrelated_control_matches=%zu\n", unrelated_matches);
    }

    free(oracle_sk);
    return 0;
}
