#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "KEM_AlgorithmInstance.h"
#include "drng.h"

DRNG_ctx drng_algorithm;

static int all_same(const unsigned char *p, size_t n, unsigned char value)
{
    size_t i;
    for (i = 0; i < n; i++) {
        if (p[i] != value) {
            return 0;
        }
    }
    return 1;
}

static void report(const char *name, int ok, int rc, unsigned long long len)
{
    printf("CASE %s ok=%d rc=%d len=%llu\n", name, ok, rc, len);
}

int main(void)
{
    unsigned char seed[64];
    unsigned char *pk, *sk, *ct, *ct2, *ss, *ss2, *ss3;
    unsigned long long pk_len = kem_get_pk_len_bytes();
    unsigned long long sk_len = kem_get_sk_len_bytes();
    unsigned long long ct_len = kem_get_ct_len_bytes();
    unsigned long long ss_len = kem_get_ss_len_bytes();
    unsigned long long out_len;
    int rc;
    int ok;

    memset(seed, 0x5a, sizeof(seed));
    init_random_number(&drng_algorithm, seed, sizeof(seed) * 8);

    pk = calloc((size_t)pk_len, 1);
    sk = calloc((size_t)sk_len, 1);
    ct = calloc((size_t)ct_len, 1);
    ct2 = calloc((size_t)ct_len, 1);
    ss = calloc((size_t)ss_len, 1);
    ss2 = calloc((size_t)ss_len, 1);
    ss3 = calloc((size_t)ss_len, 1);
    if (!pk || !sk || !ct || !ct2 || !ss || !ss2 || !ss3) {
        return 2;
    }

    out_len = pk_len + 1;
    rc = kem_keygen(pk, &out_len, sk, &sk_len);
    report("keygen_bad_pk_length", rc != 0 && out_len == pk_len, rc, out_len);

    pk_len = kem_get_pk_len_bytes();
    sk_len = kem_get_sk_len_bytes();
    rc = kem_keygen(pk, &pk_len, sk, &sk_len);
    report("keygen", rc == 0, rc, pk_len);

    ss_len = kem_get_ss_len_bytes();
    ct_len = kem_get_ct_len_bytes();
    rc = kem_enc(pk, pk_len, ss, &ss_len, ct, &ct_len);
    report("encaps", rc == 0, rc, ct_len);

    out_len = kem_get_ss_len_bytes();
    rc = kem_dec(sk, kem_get_sk_len_bytes(), ct, ct_len, ss2, &out_len);
    ok = rc == 0 && out_len == kem_get_ss_len_bytes() &&
         memcmp(ss, ss2, out_len) == 0;
    report("valid_decaps", ok, rc, out_len);

    ss_len = kem_get_ss_len_bytes();
    ct_len = kem_get_ct_len_bytes();
    rc = kem_enc(pk, kem_get_pk_len_bytes(), ss2, &ss_len, ct2, &ct_len);
    ok = rc == 0 && memcmp(ct, ct2, ct_len) != 0 &&
         memcmp(ss, ss2, ss_len) != 0;
    report("fresh_encapsulation_differs", ok, rc, ct_len);

    out_len = kem_get_ss_len_bytes();
    rc = kem_dec(sk, kem_get_sk_len_bytes(), ct2, ct_len, ss3, &out_len);
    ok = rc == 0 && memcmp(ss2, ss3, out_len) == 0;
    report("second_valid_decaps", ok, rc, out_len);

    ct[0] ^= 1;
    out_len = kem_get_ss_len_bytes();
    memset(ss2, 0, out_len);
    rc = kem_dec(sk, kem_get_sk_len_bytes(), ct, ct_len, ss2, &out_len);
    report("mutated_first_byte_rejected", rc != 0 && !all_same(ss2, out_len, 0),
           rc, out_len);
    memset(ss3, 0, out_len);
    rc = kem_dec(sk, kem_get_sk_len_bytes(), ct, ct_len, ss3, &out_len);
    report("mutated_first_byte_fallback_stable",
           rc != 0 && memcmp(ss2, ss3, out_len) == 0, rc, out_len);

    ct[0] ^= 1;
    ct[ct_len - 1] ^= 1;
    out_len = kem_get_ss_len_bytes();
    rc = kem_dec(sk, kem_get_sk_len_bytes(), ct, ct_len, ss2, &out_len);
    report("mutated_salt_rejected", rc != 0, rc, out_len);
    ct[ct_len - 1] ^= 1;

    out_len = kem_get_ss_len_bytes();
    rc = kem_dec(sk, kem_get_sk_len_bytes(), ct, ct_len - 1, ss2, &out_len);
    report("decaps_bad_ct_length", rc != 0 && out_len == kem_get_ss_len_bytes(),
           rc, out_len);

    ss_len = kem_get_ss_len_bytes();
    ct_len = kem_get_ct_len_bytes() - 1;
    rc = kem_enc(pk, kem_get_pk_len_bytes(), ss2, &ss_len, ct2, &ct_len);
    report("encaps_bad_ct_length", rc != 0 && ss_len == kem_get_ss_len_bytes() &&
           ct_len == kem_get_ct_len_bytes(), rc, ct_len);

    pk[pk_len - 1] |= 1;
    ss_len = kem_get_ss_len_bytes();
    ct_len = kem_get_ct_len_bytes();
    rc = kem_enc(pk, pk_len, ss2, &ss_len, ct2, &ct_len);
    report("public_key_padding_rejected", rc != 0, rc, ct_len);
    pk[pk_len - 1] &= 0xfe;

    sk[kem_get_pk_len_bytes() - 1] |= 1;
    out_len = kem_get_ss_len_bytes();
    rc = kem_dec(sk, kem_get_sk_len_bytes(), ct, ct_len, ss2, &out_len);
    report("secret_key_padding_rejected", rc != 0, rc, out_len);

    rc = kem_enc(NULL, pk_len, ss2, &ss_len, ct2, &ct_len);
    report("encaps_null_pk", rc != 0, rc, ss_len);
    rc = kem_enc(pk, pk_len, ss2, NULL, ct2, &ct_len);
    report("encaps_null_ss_len", rc != 0, rc, ct_len);

    printf("SUMMARY parameter_set=%s pk=%llu sk=%llu ct=%llu ss=%llu\n",
           ALGORITHM_INSTANCE,
           kem_get_pk_len_bytes(), kem_get_sk_len_bytes(),
           kem_get_ct_len_bytes(), kem_get_ss_len_bytes());

    free(ss3);
    free(ss2);
    free(ss);
    free(ct2);
    free(ct);
    free(sk);
    free(pk);
    return 0;
}
