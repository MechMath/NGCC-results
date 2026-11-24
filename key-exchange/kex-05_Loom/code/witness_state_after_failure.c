#include <stdio.h>
#include <string.h>

#include "KEX_LoomKEX-128.h"
#include "drng.h"

DRNG_ctx drng_algorithm;

static int walk_to_msg4(
    unsigned char pka[CRYPTO_LOOM_PUBLICKEYBYTES],
    unsigned char ska[CRYPTO_LOOM_SECRETKEYBYTES],
    unsigned char pkb[CRYPTO_LOOM_PUBLICKEYBYTES],
    unsigned char skb[CRYPTO_LOOM_SECRETKEYBYTES],
    unsigned char sta[16384],
    unsigned char stb[16384],
    unsigned char m1[CRYPTO_LOOM_MSG1BYTES],
    unsigned char m2[CRYPTO_LOOM_MSG2BYTES],
    unsigned char m3[CRYPTO_LOOM_MSG3BYTES],
    unsigned char m4[CRYPTO_LOOM_MSG4BYTES])
{
    unsigned long long pka_len, ska_len, pkb_len, skb_len;
    unsigned long long sta_len, stb_len, m1_len, m2_len, m3_len, m4_len;
    unsigned char seed[64];
    int ret;

    memset(seed, 0xA5, sizeof(seed));
    init_random_number(&drng_algorithm, seed, sizeof(seed));
    pka_len = ska_len = pkb_len = skb_len = 16384;
    sta_len = stb_len = m1_len = m2_len = m3_len = m4_len = 16384;

    ret = kex_init_a(pka, &pka_len, ska, &ska_len, sta, &sta_len);
    if (ret) return ret;
    ret = kex_init_b(pkb, &pkb_len, skb, &skb_len, stb, &stb_len);
    if (ret) return ret;
    ret = kex_generate_pass1_msg_a(
        ska, ska_len, pkb, pkb_len, sta, &sta_len, m1, &m1_len);
    if (ret) return ret;
    ret = kex_generate_pass2_msg_b(
        skb, skb_len, pka, pka_len, m1, m1_len, stb, &stb_len, m2, &m2_len);
    if (ret) return ret;
    ret = kex_generate_pass3_msg_a(
        ska, ska_len, pkb, pkb_len, m2, m2_len, sta, &sta_len, m3, &m3_len);
    if (ret) return ret;
    return kex_generate_pass4_msg_b(
        skb, skb_len, pka, pka_len, m3, m3_len, stb, &stb_len, m4, &m4_len);
}

static int walk_to_msg2(
    unsigned char pka[CRYPTO_LOOM_PUBLICKEYBYTES],
    unsigned char ska[CRYPTO_LOOM_SECRETKEYBYTES],
    unsigned char pkb[CRYPTO_LOOM_PUBLICKEYBYTES],
    unsigned char skb[CRYPTO_LOOM_SECRETKEYBYTES],
    unsigned char sta[16384],
    unsigned char stb[16384],
    unsigned char m1[CRYPTO_LOOM_MSG1BYTES],
    unsigned char m2[CRYPTO_LOOM_MSG2BYTES])
{
    unsigned long long pka_len = 16384, ska_len = 16384;
    unsigned long long pkb_len = 16384, skb_len = 16384;
    unsigned long long sta_len = 16384, stb_len = 16384;
    unsigned long long m1_len = 16384, m2_len = 16384;
    int ret;

    ret = kex_init_a(pka, &pka_len, ska, &ska_len, sta, &sta_len);
    if (ret) return ret;
    ret = kex_init_b(pkb, &pkb_len, skb, &skb_len, stb, &stb_len);
    if (ret) return ret;
    ret = kex_generate_pass1_msg_a(
        ska, ska_len, pkb, pkb_len, sta, &sta_len, m1, &m1_len);
    if (ret) return ret;
    return kex_generate_pass2_msg_b(
        skb, skb_len, pka, pka_len, m1, m1_len, stb, &stb_len, m2, &m2_len);
}

int main(void)
{
    unsigned char pka[CRYPTO_LOOM_PUBLICKEYBYTES];
    unsigned char ska[CRYPTO_LOOM_SECRETKEYBYTES];
    unsigned char pkb[CRYPTO_LOOM_PUBLICKEYBYTES];
    unsigned char skb[CRYPTO_LOOM_SECRETKEYBYTES];
    unsigned char sta[16384], stb[16384];
    unsigned char saved[16384];
    unsigned char m1[CRYPTO_LOOM_MSG1BYTES];
    unsigned char m2[CRYPTO_LOOM_MSG2BYTES];
    unsigned char m2_good[CRYPTO_LOOM_MSG2BYTES];
    unsigned char m3[CRYPTO_LOOM_MSG3BYTES];
    unsigned char m4[CRYPTO_LOOM_MSG4BYTES];
    unsigned char ss[CRYPTO_LOOM_SSBYTES];
    unsigned long long sta_len, saved_len, ss_len, m3_len;
    int ret;

    ret = walk_to_msg4(pka, ska, pkb, skb, sta, stb, m1, m2, m3, m4);
    if (ret != 1) {
        fprintf(stderr, "walk failed: %d\n", ret);
        return 2;
    }

    sta_len = kex_get_sta_len_bytes();
    saved_len = sta_len;
    memcpy(saved, sta, sizeof(saved));

    {
        size_t idlen = (size_t)m4[0] | ((size_t)m4[1] << 8);
        size_t taulen = (size_t)m4[2 + idlen] | ((size_t)m4[3 + idlen] << 8);
        size_t tauoff = 2 + idlen + 2 + taulen;
        m4[tauoff] ^= 1;
    }
    ss_len = sizeof(ss);
    ret = kex_derive_ss_a(
        ska, kex_get_sk_len_bytes(), pkb, kex_get_pk_len_bytes(),
        m4, CRYPTO_LOOM_MSG4BYTES, sta, sta_len, ss, &ss_len);
    printf("confirm_ret=%d state_unchanged=%d\n",
           ret, memcmp(saved, sta, (size_t)saved_len) == 0);

    ret = walk_to_msg2(pka, ska, pkb, skb, sta, stb, m1, m2);
    if (ret) {
        fprintf(stderr, "msg2 walk failed: %d\n", ret);
        return 2;
    }
    saved_len = kex_get_sta_len_bytes();
    memcpy(saved, sta, sizeof(saved));
    memcpy(m2_good, m2, sizeof(m2_good));
    m2[100] ^= 1;
    m3_len = 0;
    ret = kex_generate_pass3_msg_a(
        ska, kex_get_sk_len_bytes(), pkb, kex_get_pk_len_bytes(),
        m2, CRYPTO_LOOM_MSG2BYTES, sta, &sta_len, m3, &m3_len);
    printf("decaps1_ret=%d state_unchanged=%d\n",
           ret, memcmp(saved, sta, (size_t)saved_len) == 0);
    m2[101] ^= 1;
    ret = kex_generate_pass3_msg_a(
        ska, kex_get_sk_len_bytes(), pkb, kex_get_pk_len_bytes(),
        m2, CRYPTO_LOOM_MSG2BYTES, sta, &sta_len, m3, &m3_len);
    printf("decaps2_ret=%d state_unchanged=%d\n",
           ret, memcmp(saved, sta, (size_t)saved_len) == 0);
    ret = kex_generate_pass3_msg_a(
        ska, kex_get_sk_len_bytes(), pkb, kex_get_pk_len_bytes(),
        m2_good, CRYPTO_LOOM_MSG2BYTES, sta, &sta_len, m3, &m3_len);
    printf("valid_retry_ret=%d stage_after=%u\n", ret, (unsigned)sta[7]);
    return 0;
}
