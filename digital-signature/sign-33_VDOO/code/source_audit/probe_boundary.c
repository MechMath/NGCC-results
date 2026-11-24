#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "SIG_AlgorithmInstance.h"
#include "drng.h"
#include "rng.h"

DRNG_ctx drng_algorithm;

int main(void)
{
    unsigned char seed[48];
    memset(seed, 0x42, sizeof(seed));
    init_randombytes(seed, sizeof(seed));

    unsigned long long pk_len = sig_get_pk_len_bytes();
    unsigned long long sk_len = sig_get_sk_len_bytes();
    unsigned long long sn_len = sig_get_sn_len_bytes();
    unsigned char *pk = calloc(pk_len, 1);
    unsigned char *sk = calloc(sk_len, 1);
    unsigned char *sn = calloc(sn_len, 1);
    if (!pk || !sk || !sn || sig_keygen(pk, &pk_len, sk, &sk_len) != 0) {
        return 2;
    }

    const unsigned char m[] = "pay-alice";
    const unsigned char x[] = "+mallory";
    const unsigned long long m_len = sizeof(m) - 1;
    const unsigned long long x_len = sizeof(x) - 1;
    unsigned char extended[sizeof(m) + sizeof(x)];
    memcpy(extended, m, m_len);
    memcpy(extended + m_len, x, x_len);
    const unsigned long long extended_len = m_len + x_len;

    if (sig_sign(sk, sk_len, extended, extended_len, sn, &sn_len) != 0) {
        return 3;
    }

    int exact_control = sig_verify(pk, pk_len, sn, sn_len, extended, extended_len);

    unsigned long long forged_len = x_len + sn_len;
    unsigned char *forged = malloc(forged_len);
    memcpy(forged, x, x_len);
    memcpy(forged + x_len, sn, sn_len);
    int forged_verdict = sig_verify(pk, pk_len, forged, forged_len, (unsigned char *)m, m_len);

    int short_control = sig_verify(pk, pk_len, sn, sn_len - 1, (unsigned char *)m, m_len);

    printf("exact_signature_on_extended_message=%d\n", exact_control);
    printf("overlong_repack_verifies_for_original_message=%d\n", forged_verdict);
    printf("one_byte_short_signature_for_original_message=%d\n", short_control);
    printf("original_message_len=%llu extension_len=%llu original_signature_len=%llu repacked_signature_len=%llu\n",
           m_len, x_len, sn_len, forged_len);
    return 0;
}
