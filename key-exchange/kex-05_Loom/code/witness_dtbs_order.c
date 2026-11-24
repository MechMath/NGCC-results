#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "KEX_LoomKEX-128.h"
#include "drng.h"
#include "sign.h"

DRNG_ctx drng_algorithm;

int main(void)
{
    unsigned char pka[CRYPTO_LOOM_PUBLICKEYBYTES];
    unsigned char ska[CRYPTO_LOOM_SECRETKEYBYTES];
    unsigned char pkb[CRYPTO_LOOM_PUBLICKEYBYTES];
    unsigned char skb[CRYPTO_LOOM_SECRETKEYBYTES];
    unsigned char sta[16384], stb[16384];
    unsigned char m1[CRYPTO_LOOM_MSG1BYTES];
    unsigned char m2[CRYPTO_LOOM_MSG2BYTES];
    unsigned char m3[CRYPTO_LOOM_MSG3BYTES];
    unsigned char dtbs_spec[1 + 8 +
                            CRYPTO_LOOM_KEM_PKBYTES +
                            CRYPTO_LOOM_KEM_CTBYTES];
    unsigned char dtbs_impl[sizeof(dtbs_spec)];
    unsigned char seed[64];
    unsigned long long pka_len = 16384, ska_len = 16384;
    unsigned long long pkb_len = 16384, skb_len = 16384;
    unsigned long long sta_len = 16384, stb_len = 16384;
    unsigned long long m1_len = 16384, m2_len = 16384, m3_len = 16384;
    const unsigned char *sigma;
    size_t idlen, siglen, off, dtbs_len;
    int ret_spec, ret_impl;

    memset(seed, 0xA5, sizeof(seed));
    init_random_number(&drng_algorithm, seed, sizeof(seed));

    if (kex_init_a(pka, &pka_len, ska, &ska_len, sta, &sta_len)) return 2;
    if (kex_init_b(pkb, &pkb_len, skb, &skb_len, stb, &stb_len)) return 2;
    if (kex_generate_pass1_msg_a(
            ska, ska_len, pkb, pkb_len, sta, &sta_len, m1, &m1_len)) return 2;
    if (kex_generate_pass2_msg_b(
            skb, skb_len, pka, pka_len, m1, m1_len,
            stb, &stb_len, m2, &m2_len)) return 2;
    if (kex_generate_pass3_msg_a(
            ska, ska_len, pkb, pkb_len, m2, m2_len,
            sta, &sta_len, m3, &m3_len)) return 2;

    idlen = (size_t)m3[0] | ((size_t)m3[1] << 8);
    siglen = (size_t)m3[2 + idlen] | ((size_t)m3[3 + idlen] << 8);
    sigma = m3 + 2 + idlen + 2;

    dtbs_spec[0] = 0;
    memcpy(dtbs_spec + 1, m2, 8);
    memcpy(dtbs_spec + 9, m1 + 8, CRYPTO_LOOM_KEM_PKBYTES);
    off = 1 + 8 + CRYPTO_LOOM_KEM_PKBYTES;
    memcpy(dtbs_spec + off, m2 + 8, CRYPTO_LOOM_KEM_CTBYTES);
    dtbs_len = off + CRYPTO_LOOM_KEM_CTBYTES;

    memcpy(dtbs_impl, m2, 8);
    dtbs_impl[8] = 0;
    memcpy(dtbs_impl + 9, m1 + 8, CRYPTO_LOOM_KEM_PKBYTES);
    memcpy(dtbs_impl + 9 + CRYPTO_LOOM_KEM_PKBYTES,
           m2 + 8, CRYPTO_LOOM_KEM_CTBYTES);

    ret_spec = crypto_sign_verify(
        sigma, siglen, dtbs_spec, dtbs_len, pka);
    ret_impl = crypto_sign_verify(
        sigma, siglen, dtbs_impl, dtbs_len, pka);

    printf("siglen=%zu spec_order_verify=%d impl_order_verify=%d\n",
           siglen, ret_spec, ret_impl);
    return (ret_spec != 0 && ret_impl == 0) ? 0 : 1;
}
