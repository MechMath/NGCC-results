#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "KEX_AlgorithmInstance.h"

static int same_bytes(const unsigned char *a, const unsigned char *b, size_t n)
{
    return memcmp(a, b, n) == 0;
}

static size_t nonzero_bytes(const unsigned char *p, size_t n)
{
    size_t count = 0;
    for (size_t i = 0; i < n; ++i)
        count += p[i] != 0;
    return count;
}

int main(void)
{
    const size_t pk_len = (size_t)kex_get_pk_len_bytes();
    const size_t sk_len = (size_t)kex_get_sk_len_bytes();
    const size_t sta_len = (size_t)kex_get_sta_len_bytes();
    const size_t stb_len = (size_t)kex_get_stb_len_bytes();
    const size_t ss_len = (size_t)kex_get_ss_len_bytes();
    const size_t total_msg = (size_t)kex_get_total_msg_len_bytes();
    const size_t m1_len_expected = total_msg -
        (2 * 4 + 2 * 4086); /* table-derived M2 length */
    const size_t m2_len_expected = 2 * 4 + 2 * 4086;
    unsigned long long pka_len = 0, ska_len = 0, inita_len = 0;
    unsigned long long pkb_len = 0, skb_len = 0, initb_len = 0;
    unsigned long long sta_len_actual = 0, m1_len = 0;
    unsigned long long stb_len_actual = 0, m2_len = 0;
    unsigned long long ssa_len = 0, ssb_len = 0;
    int init_a, init_b, pass1, pass2, derive_a, derive_b;
    int derive_a_again, derive_b_again;
    unsigned char *pka = calloc(1, pk_len);
    unsigned char *pkb = calloc(1, pk_len);
    unsigned char *ska = calloc(1, sk_len);
    unsigned char *skb = calloc(1, sk_len);
    unsigned char *sta = calloc(1, sta_len);
    unsigned char *stb = calloc(1, stb_len);
    unsigned char *m1 = calloc(1, m1_len_expected);
    unsigned char *m2 = calloc(1, m2_len_expected);
    unsigned char *ssa = calloc(1, ss_len);
    unsigned char *ssb = calloc(1, ss_len);
    unsigned char *sta_before = calloc(1, sta_len);
    unsigned char *stb_before = calloc(1, stb_len);
    unsigned char *null_out = calloc(1, 1);

    if (!pka || !pkb || !ska || !skb || !sta || !stb || !m1 || !m2 ||
        !ssa || !ssb || !sta_before || !stb_before || !null_out)
        return 2;

    init_a = kex_init_a(pka, &pka_len, ska, &ska_len, sta, &inita_len);
    init_b = kex_init_b(pkb, &pkb_len, skb, &skb_len, stb, &initb_len);
    pass1 = kex_generate_pass1_msg_a(ska, ska_len, pkb, pkb_len, sta,
                                     &sta_len_actual, m1, &m1_len);
    pass2 = kex_generate_pass2_msg_b(skb, skb_len, pka, pka_len, m1, m1_len,
                                     stb, &stb_len_actual, m2, &m2_len);

    memcpy(sta_before, sta, sta_len);
    memcpy(stb_before, stb, stb_len);
    derive_a = kex_derive_ss_a(ska, ska_len, pkb, pkb_len, m2, m2_len,
                               sta, sta_len_actual, ssa, &ssa_len);
    derive_b = kex_derive_ss_b(skb, skb_len, pka, pka_len, m1, m1_len,
                               stb, stb_len_actual, ssb, &ssb_len);
    derive_a_again = kex_derive_ss_a(ska, ska_len, pkb, pkb_len, m2, m2_len,
                                     sta, sta_len_actual, ssa, &ssa_len);
    derive_b_again = kex_derive_ss_b(skb, skb_len, pka, pka_len, m1, m1_len,
                                     stb, stb_len_actual, ssb, &ssb_len);

    printf("status init_a=%d init_b=%d pass1=%d pass2=%d derive_a=%d "
           "derive_b=%d derive_a_again=%d derive_b_again=%d\n",
           init_a, init_b, pass1, pass2, derive_a, derive_b,
           derive_a_again, derive_b_again);
    printf("lengths pka=%llu ska=%llu sta=%llu m1=%llu stb=%llu m2=%llu "
           "ssa=%llu ssb=%llu\n",
           pka_len, ska_len, sta_len_actual, m1_len, stb_len_actual, m2_len,
           ssa_len, ssb_len);
    printf("shared_equal=%d sta_unchanged_after_derive=%d "
           "stb_unchanged_after_derive=%d\n",
           same_bytes(ssa, ssb, ss_len),
           same_bytes(sta, sta_before, sta_len),
           same_bytes(stb, stb_before, stb_len));
    printf("post_derive_nonzero sta[dK_T]=%zu sta[K_A]=%zu "
           "stb[K_A]=%zu stb[K_B]=%zu stb[K_T]=%zu\n",
           nonzero_bytes(sta + 4086 + 2054, 2102),
           nonzero_bytes(sta + 4086 + 2054 + 2102, 16),
           nonzero_bytes(stb + 2 * 4086, 16),
           nonzero_bytes(stb + 2 * 4086 + 16, 16),
           nonzero_bytes(stb + 2 * 4086 + 32, 16));

    m2[0] ^= 1;
    printf("bad_m2_id_status=%d\n",
           kex_derive_ss_a(ska, ska_len, pkb, pkb_len, m2, m2_len,
                           sta, sta_len_actual, ssa, &ssa_len));
    m2[0] ^= 1;

    printf("bad_m1_length_status=%d\n",
           kex_generate_pass2_msg_b(skb, skb_len, pka, pka_len, m1,
                                    m1_len - 1, stb, &stb_len_actual, m2,
                                    &m2_len));
    printf("pass3_status=%d\n",
           kex_generate_pass3_msg_a(ska, ska_len, pkb, pkb_len, m2, m2_len,
                                    sta, &sta_len_actual, null_out,
                                    &m1_len));

    free(pka); free(pkb); free(ska); free(skb); free(sta); free(stb);
    free(m1); free(m2); free(ssa); free(ssb); free(sta_before);
    free(stb_before); free(null_out);
    return 0;
}
