#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "SIG_AlgorithmInstance.h"
#include "drng.h"

DRNG_ctx drng_algorithm;

#ifdef AUDIT_INSTRUMENTED
extern unsigned long long facto_audit_trials;
extern unsigned long long facto_audit_sample_fail;
extern unsigned long long facto_audit_poly_fail;
extern unsigned long long facto_audit_factor_fail;
extern unsigned long long facto_audit_expand_fail;
extern unsigned long long facto_audit_split_fail;
extern unsigned long long facto_audit_split_success;
extern unsigned long long facto_audit_scale_attempts;
extern unsigned long long facto_audit_scale_success;
extern unsigned long long facto_audit_scale_success_by_index[64];
extern unsigned long long facto_audit_total_scale_success_by_index[64];
extern unsigned long long facto_audit_sign_fail;
#endif

static const unsigned long long lengths[] = {0, 1, 31, 32, 33, 56, 64, 128};

static uint64_t fnv1a(const unsigned char *p, size_t n)
{
    uint64_t h = UINT64_C(1469598103934665603);
    for (size_t i = 0; i < n; i++) {
        h ^= p[i];
        h *= UINT64_C(1099511628211);
    }
    return h;
}

static void seed_for(const char *domain, unsigned long long a,
                     unsigned long long b, unsigned char seed[64])
{
    const unsigned char *d = (const unsigned char *)domain;
    size_t dn = strlen(domain);
    for (size_t i = 0; i < 64; i++) {
        uint64_t x = (uint64_t)(i + 1) * UINT64_C(0x9e3779b97f4a7c15);
        x ^= a * UINT64_C(0xbf58476d1ce4e5b9);
        x ^= b * UINT64_C(0x94d049bb133111eb);
        x ^= (uint64_t)d[i % dn] << ((i & 7u) * 8u);
        x ^= x >> 30;
        x *= UINT64_C(0xbf58476d1ce4e5b9);
        x ^= x >> 27;
        x *= UINT64_C(0x94d049bb133111eb);
        x ^= x >> 31;
        seed[i] = (unsigned char)(x >> ((i & 7u) * 8u));
    }
}

static int reseed(const char *domain, unsigned long long a,
                  unsigned long long b)
{
    unsigned char seed[64];
    seed_for(domain, a, b, seed);
    return init_random_number(&drng_algorithm, seed, sizeof(seed));
}

static void fill_message(unsigned char *m, unsigned long long len,
                         unsigned long long key_index,
                         unsigned long long length_index)
{
    for (unsigned long long i = 0; i < len; i++) {
        m[i] = (unsigned char)(0x20u + ((i * 131u + key_index * 17u +
                                        length_index * 29u) & 0x5fu));
    }
}

static void print_audit(void)
{
#ifdef AUDIT_INSTRUMENTED
    printf(",%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu",
           facto_audit_trials, facto_audit_sample_fail,
           facto_audit_poly_fail, facto_audit_factor_fail,
           facto_audit_expand_fail, facto_audit_split_fail,
           facto_audit_split_success, facto_audit_scale_attempts,
           facto_audit_scale_success, facto_audit_sign_fail);
#else
    printf(",0,0,0,0,0,0,0,0,0,0");
#endif
}

static int run_population(unsigned long long keys,
                          unsigned long long messages_per_length,
                          unsigned long long first_key)
{
    const unsigned long long pk_len = sig_get_pk_len_bytes();
    const unsigned long long sk_len = sig_get_sk_len_bytes();
    const unsigned long long sn_len_max = sig_get_sn_len_bytes();
    unsigned char *pk = malloc((size_t)pk_len);
    unsigned char *sk = malloc((size_t)sk_len);
    unsigned char *sn = malloc((size_t)sn_len_max + 1);
    unsigned char *msg = malloc(128);
    unsigned long long failures = 0;
    unsigned long long verify_failures = 0;
    unsigned long long calls = 0;

    if (!pk || !sk || !sn || !msg) {
        fprintf(stderr, "allocation failure\n");
        return 2;
    }

    printf("kind,key,length,keygen_rc,keygen_pk_len,keygen_sk_len,"
           "sign_rc,sign_sn_len,verify_rc,pk_fnv,sk_fnv,msg_fnv,sig_fnv,"
           "trials,sample_fail,poly_fail,factor_fail,expand_fail,"
           "split_fail,split_success,scale_attempts,scale_success,sign_fail\n");

    for (unsigned long long k = first_key; k < first_key + keys; k++) {
        unsigned long long pk_out = pk_len;
        unsigned long long sk_out = sk_len;
        int kg;

        if (reseed("keygen", k, 0) != 0) {
            fprintf(stderr, "keygen DRNG init failed\n");
            return 3;
        }
        kg = sig_keygen(pk, &pk_out, sk, &sk_out);

        for (unsigned long long li = 0; li < sizeof(lengths) / sizeof(lengths[0]); li++) {
            for (unsigned long long j = 0; j < messages_per_length; j++) {
                unsigned long long sn_out = sn_len_max;
                int sr;
                int vr = -999;
                calls++;
                fill_message(msg, lengths[li], k, li * 97 + j);
                if (reseed("sign", k, li * 1000003ULL + j) != 0) {
                    fprintf(stderr, "sign DRNG init failed\n");
                    return 4;
                }
                sr = sig_sign(sk, sk_out, msg, lengths[li], sn, &sn_out);
                if (sr == 0) {
                    vr = sig_verify(pk, pk_out, sn, sn_out, msg, lengths[li]);
                }
                printf("population,%llu,%llu,%d,%llu,%llu,%d,%llu,%d,"
                       "%016llx,%016llx,%016llx,%016llx",
                       k, lengths[li], kg, pk_out, sk_out, sr, sn_out, vr,
                       (unsigned long long)fnv1a(pk, (size_t)pk_out),
                       (unsigned long long)fnv1a(sk, (size_t)sk_out),
                       (unsigned long long)fnv1a(msg, (size_t)lengths[li]),
                       (unsigned long long)fnv1a(sn, (size_t)sn_out));
                print_audit();
                printf("\n");
                if (sr != 0) failures++;
                if (sr == 0 && vr != 0) verify_failures++;
            }
        }
    }
    printf("summary,calls=%llu,sign_failures=%llu,verify_failures=%llu\n",
           calls, failures, verify_failures);
#ifdef AUDIT_INSTRUMENTED
    for (int i = 0; i < 64; i++) {
        if (facto_audit_total_scale_success_by_index[i] != 0) {
            printf("scale_success_index,%d,%llu\n", i,
                   facto_audit_total_scale_success_by_index[i]);
        }
    }
#endif
    free(msg);
    free(sn);
    free(sk);
    free(pk);
    return 0;
}

static int verify_expect(const char *label,
                         unsigned char *pk, unsigned long long pk_len,
                         unsigned char *sn, unsigned long long sn_len,
                         unsigned char *m, unsigned long long m_len,
                         int expect_zero)
{
    int rc = sig_verify(pk, pk_len, sn, sn_len, m, m_len);
    int ok = expect_zero ? (rc == 0) : (rc != 0);
    printf("malformed,%s,rc=%d,expect_zero=%d,ok=%d\n",
           label, rc, expect_zero, ok);
    return ok;
}

static int run_controls(void)
{
    const unsigned long long pk_len = sig_get_pk_len_bytes();
    const unsigned long long sk_len = sig_get_sk_len_bytes();
    const unsigned long long sn_len_const = sig_get_sn_len_bytes();
    unsigned char *pk = calloc((size_t)pk_len, 1);
    unsigned char *pk_bad = calloc((size_t)pk_len, 1);
    unsigned char *pk_copy = calloc((size_t)pk_len, 1);
    unsigned char *sk = calloc((size_t)sk_len, 1);
    unsigned char *sk_copy = calloc((size_t)sk_len, 1);
    unsigned char *sn1 = calloc((size_t)sn_len_const + 1, 1);
    unsigned char *sn2 = calloc((size_t)sn_len_const + 1, 1);
    unsigned char *msg = malloc(128);
    unsigned long long pk_out = pk_len, sk_out = sk_len;
    unsigned long long sn1_out = sn_len_const, sn2_out = sn_len_const;
    int kg, s1, s2, v1, v2, rc;
    int controls_ok = 1;

    if (!pk || !pk_bad || !pk_copy || !sk || !sk_copy || !sn1 || !sn2 || !msg) return 2;
    fill_message(msg, 64, 0, 0);

    if (reseed("controls", 1, 1) != 0) return 3;
    kg = sig_keygen(pk, &pk_out, sk, &sk_out);
    s1 = sig_sign(sk, sk_out, msg, 64, sn1, &sn1_out);
    s2 = sig_sign(sk, sk_out, msg, 64, sn2, &sn2_out);
    v1 = s1 == 0 ? sig_verify(pk, pk_out, sn1, sn1_out, msg, 64) : -999;
    v2 = s2 == 0 ? sig_verify(pk, pk_out, sn2, sn2_out, msg, 64) : -999;
    printf("repeat,keygen=%d,sign1=%d,sign2=%d,verify1=%d,verify2=%d,"
           "same_signature=%d\n", kg, s1, s2, v1, v2,
           s1 == 0 && s2 == 0 && sn1_out == sn2_out &&
           memcmp(sn1, sn2, (size_t)sn1_out) == 0);
    memcpy(pk_copy, pk, (size_t)pk_out);
    memcpy(sk_copy, sk, (size_t)sk_out);

    if (reseed("controls", 1, 1) != 0) return 3;
    pk_out = pk_len;
    sk_out = sk_len;
    sn2_out = sn_len_const;
    kg = sig_keygen(pk, &pk_out, sk, &sk_out);
    s2 = sig_sign(sk, sk_out, msg, 64, sn2, &sn2_out);
    printf("replay,keygen=%d,sign=%d,same_keygen_bytes=%d,same_signature=%d\n",
           kg, s2,
           kg == 0 && memcmp(pk_copy, pk, (size_t)pk_len) == 0 &&
               memcmp(sk_copy, sk, (size_t)sk_len) == 0,
           kg == 0 && s2 == 0 && memcmp(sn1, sn2, (size_t)sn1_out) == 0);

    controls_ok &= verify_expect("positive", pk, pk_out, sn1, sn1_out, msg, 64, 1);
    controls_ok &= verify_expect("changed_message", pk, pk_out, sn1, sn1_out, msg, 63, 0);
    sn2_out = sn1_out;
    memcpy(sn2, sn1, (size_t)sn1_out);
    sn2[0] ^= 1;
    controls_ok &= verify_expect("signature_bitflip", pk, pk_out, sn2, sn2_out, msg, 64, 0);
    memcpy(sn2, sn1, (size_t)sn1_out);
    sn2[0] = 0xff;
    sn2[1] = 0xff;
    controls_ok &= verify_expect("signature_noncanonical", pk, pk_out, sn2, sn2_out, msg, 64, 0);
    controls_ok &= verify_expect("signature_short", pk, pk_out, sn1, sn1_out - 1, msg, 64, 0);
    memcpy(pk_bad, pk, (size_t)pk_len);
    pk_bad[0] = 0xff;
    pk_bad[1] = 0xff;
    controls_ok &= verify_expect("public_key_noncanonical", pk_bad, pk_len, sn1, sn1_out, msg, 64, 0);
    controls_ok &= verify_expect("public_key_short", pk, pk_len - 1, sn1, sn1_out, msg, 64, 0);

    rc = sig_verify(NULL, pk_len, sn1, sn1_out, msg, 64);
    printf("api,sig_verify_null_pk,rc=%d,rejected=%d\n", rc, rc != 0);
    controls_ok &= rc != 0;
    rc = sig_verify(pk, pk_len, NULL, sn1_out, msg, 64);
    printf("api,sig_verify_null_sig,rc=%d,rejected=%d\n", rc, rc != 0);
    controls_ok &= rc != 0;
    rc = sig_verify(pk, pk_len, sn1, sn1_out, NULL, 0);
    printf("api,sig_verify_null_message,rc=%d,rejected=%d\n", rc, rc != 0);
    controls_ok &= rc != 0;
    rc = sig_sign(NULL, sk_len, msg, 64, sn2, &sn2_out);
    printf("api,sig_sign_null_sk,rc=%d,rejected=%d\n", rc, rc != 0);
    controls_ok &= rc != 0;
    rc = sig_sign(sk, sk_len - 1, msg, 64, sn2, &sn2_out);
    printf("api,sig_sign_short_sk,rc=%d,rejected=%d\n", rc, rc != 0);
    controls_ok &= rc != 0;
    printf("controls,all_ok=%d\n", controls_ok);
    free(msg);
    free(sn2);
    free(sn1);
    free(sk_copy);
    free(sk);
    free(pk_copy);
    free(pk_bad);
    free(pk);
    return controls_ok ? 0 : 5;
}

int main(int argc, char **argv)
{
    if (argc >= 2 && strcmp(argv[1], "controls") == 0) {
        return run_controls();
    }
    if (argc >= 2 && strcmp(argv[1], "population") == 0) {
        unsigned long long keys = argc >= 3 ? strtoull(argv[2], NULL, 10) : 10;
        unsigned long long messages = argc >= 4 ? strtoull(argv[3], NULL, 10) : 4;
        unsigned long long first = argc >= 5 ? strtoull(argv[4], NULL, 10) : 0;
        return run_population(keys, messages, first);
    }
    fprintf(stderr, "usage: %s controls|population [keys] [messages_per_length] [first_key]\n",
            argv[0]);
    return 1;
}
