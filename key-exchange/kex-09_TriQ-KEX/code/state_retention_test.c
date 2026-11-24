#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "KEX_AlgorithmInstance.h"
#include "drng.h"

DRNG_ctx drng_algorithm;

static void *xcalloc(size_t count, size_t size)
{
    void *p = calloc(count, size);
    if (p == NULL) {
        fprintf(stderr, "allocation failed\n");
        exit(2);
    }
    return p;
}

static int require_zero(const char *what, int rc)
{
    if (rc != 0) {
        fprintf(stderr, "%s failed: %d\n", what, rc);
        return 0;
    }
    return 1;
}

int main(void)
{
    unsigned char deterministic_seed[64];
    unsigned long long pka_len = 0, ska_len = 0, sta_cap = 0, sta_len = 0;
    unsigned long long pkb_len = 0, skb_len = 0, stb_cap = 0, stb_len = 0;
    unsigned long long ss_len = 0;
    unsigned long long m1_len = 0, m2_len = 0, ssa_len = 0, ssb_len = 0;
    int ret;
    int ok = 1;

    const unsigned long long pk_len = kex_get_pk_len_bytes();
    const unsigned long long sk_len = kex_get_sk_len_bytes();
    const unsigned long long ss_cap = kex_get_ss_len_bytes();
    const unsigned long long total_cap = kex_get_total_msg_len_bytes();
    sta_cap = kex_get_sta_len_bytes();
    stb_cap = kex_get_stb_len_bytes();

    unsigned char *pka = xcalloc((size_t)pk_len, 1);
    unsigned char *ska = xcalloc((size_t)sk_len, 1);
    unsigned char *pkb = xcalloc((size_t)pk_len, 1);
    unsigned char *skb = xcalloc((size_t)sk_len, 1);
    unsigned char *sta = xcalloc((size_t)sta_cap, 1);
    unsigned char *stb = xcalloc((size_t)stb_cap, 1);
    unsigned char *ssa = xcalloc((size_t)ss_cap, 1);
    unsigned char *ssb = xcalloc((size_t)ss_cap, 1);
    unsigned char *recomputed_a = xcalloc((size_t)ss_cap, 1);
    unsigned char *recomputed = xcalloc((size_t)ss_cap, 1);
    unsigned char *m1 = xcalloc((size_t)total_cap, 1);
    unsigned char *m2 = xcalloc((size_t)total_cap, 1);
    unsigned char *public_skb = xcalloc((size_t)sk_len, 1);
    unsigned char *sta_before = xcalloc((size_t)sta_cap, 1);
    unsigned char *stb_before = xcalloc((size_t)stb_cap, 1);

    for (size_t i = 0; i < sizeof(deterministic_seed); i++)
        deterministic_seed[i] = (unsigned char)"seed"[i % 4];
    if (init_random_number(&drng_algorithm, deterministic_seed,
                           sizeof(deterministic_seed)) != 0) {
        fprintf(stderr, "DRNG initialization failed\n");
        return 2;
    }

    ret = kex_init_a(pka, &pka_len, ska, &ska_len, sta, &sta_len);
    ok &= require_zero("kex_init_a", ret);
    ret = kex_init_b(pkb, &pkb_len, skb, &skb_len, stb, &stb_len);
    ok &= require_zero("kex_init_b", ret);

    ret = kex_generate_pass1_msg_a(ska, ska_len, pkb, pkb_len,
                                   sta, &sta_len, m1, &m1_len);
    ok &= require_zero("kex_generate_pass1_msg_a", ret);
    ret = kex_generate_pass2_msg_b(skb, skb_len, pka, pka_len,
                                   m1, m1_len, stb, &stb_len, m2, &m2_len);
    ok &= (ret == 1);
    if (ret != 1)
        fprintf(stderr, "kex_generate_pass2_msg_b failed: %d\n", ret);

    memcpy(sta_before, sta, (size_t)sta_len);
    memcpy(stb_before, stb, (size_t)stb_len);

    ret = kex_derive_ss_a(ska, ska_len, pkb, pkb_len, m2, m2_len,
                          sta, sta_len, ssa, &ssa_len);
    ok &= require_zero("kex_derive_ss_a", ret);
    ret = kex_derive_ss_b(skb, skb_len, pka, pka_len, m1, m1_len,
                          stb, stb_len, ssb, &ssb_len);
    ok &= require_zero("kex_derive_ss_b", ret);

    const int state_a_unchanged =
        sta_len == kex_get_sta_len_bytes() &&
        memcmp(sta, sta_before, (size_t)sta_len) == 0;
    const int state_b_unchanged =
        stb_len == kex_get_stb_len_bytes() &&
        memcmp(stb, stb_before, (size_t)stb_len) == 0;
    const int honest_keys_equal =
        ssa_len == ssb_len &&
        memcmp(ssa, ssb, (size_t)ssa_len) == 0;

    ret = kex_derive_ss_a(ska, ska_len, pkb, pkb_len, m2, m2_len,
                          sta, sta_len, recomputed_a, &ss_len);
    ok &= require_zero("initiator re-derivation", ret);
    const int recomputed_from_state_a =
        ss_len == ssa_len &&
        memcmp(recomputed_a, ssa, (size_t)ss_len) == 0;

    /*
     * Public transcript reveals pka and pkb. The submitted derive_b reads only
     * pkb from the long-term-secret buffer, which begins with the public key.
     * Supply pkb there and zero the rest: no responder long-term secret is used.
     */
    memcpy(public_skb, pkb, (size_t)pkb_len);
    ret = kex_derive_ss_b(public_skb, skb_len, pka, pka_len, m1, m1_len,
                          stb, stb_len, recomputed, &ss_len);
    ok &= require_zero("public-transcript recomputation", ret);
    const int recomputed_from_state_b =
        ss_len == ssb_len &&
        memcmp(recomputed, ssb, (size_t)ss_len) == 0;

    printf("profile=%s\n", ALGORITHM_INSTANCE);
    printf("pk_len=%llu sk_len=%llu sta_len=%llu stb_len=%llu ss_len=%llu\n",
           pk_len, sk_len, sta_len, stb_len, ssa_len);
    printf("state_a_unchanged=%d state_b_unchanged=%d honest_keys_equal=%d "
           "recomputed_from_state_a=%d "
           "recomputed_from_state_b_public_transcript=%d\n",
           state_a_unchanged, state_b_unchanged, honest_keys_equal,
           recomputed_from_state_a, recomputed_from_state_b);

    ok &= state_a_unchanged && state_b_unchanged &&
          honest_keys_equal && recomputed_from_state_a &&
          recomputed_from_state_b;

    free(public_skb);
    free(stb_before);
    free(sta_before);
    free(m2);
    free(m1);
    free(recomputed);
    free(recomputed_a);
    free(ssb);
    free(ssa);
    free(stb);
    free(sta);
    free(skb);
    free(pkb);
    free(ska);
    free(pka);
    return ok ? 0 : 1;
}
