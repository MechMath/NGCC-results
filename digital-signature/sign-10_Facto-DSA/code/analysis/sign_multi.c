#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "SIG_AlgorithmInstance.h"
#include "drng.h"

DRNG_ctx drng_algorithm;

static int hex_value(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return 10 + c - 'A';
    if (c >= 'a' && c <= 'f') return 10 + c - 'a';
    return -1;
}

static int from_hex(const char *s, unsigned char *out, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        int hi = hex_value(s[2 * i]);
        int lo = hex_value(s[2 * i + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[i] = (unsigned char)((hi << 4) | lo);
    }
    return 0;
}

int main(void)
{
    static const char seed_hex[] =
        "927F06B594798A4DDFAA4F03F92AAAF04E1D453F6ED1DE19B86D3AADE048A654"
        "83DF4754049B5CD3F586406CF2C64875C51EDB576DF342B5A970F40EABC15D3C";
    static const char msg_hex[] =
        "EE402D1730D0117B9F51BE0672592FCEC438A2945A81F5D894B869DC863CCBF5"
        "7E5C8E7766D74E27E965235CD91E5E30E5583167053E1014";
    unsigned char seed[64];
    unsigned char msg[56];
    const unsigned long long pk_len = sig_get_pk_len_bytes();
    const unsigned long long sk_len = sig_get_sk_len_bytes();
    const unsigned long long sn_len = sig_get_sn_len_bytes();
    unsigned char *pk = calloc((size_t)pk_len, 1);
    unsigned char *sk = calloc((size_t)sk_len, 1);
    unsigned char *sn = calloc((size_t)sn_len, 1);
    unsigned long long out_pk = pk_len, out_sk = sk_len, out_sn = sn_len;

    if (!pk || !sk || !sn) return 2;
    if (from_hex(seed_hex, seed, sizeof seed) != 0 ||
        from_hex(msg_hex, msg, sizeof msg) != 0) return 3;
    if (init_random_number(&drng_algorithm, seed, sizeof seed) != 0) return 4;
    if (sig_keygen(pk, &out_pk, sk, &out_sk) != 0) return 5;

    for (int i = 0; i < 12; i++) {
        int rc;
        out_sn = sn_len;
        rc = sig_sign(sk, out_sk, msg, sizeof msg, sn, &out_sn);
        if (rc != 0 || sig_verify(pk, out_pk, sn, out_sn, msg, sizeof msg) != 0) {
            fprintf(stderr, "sign[%d] failed: sign=%d\n", i, rc);
            return 6;
        }
        printf("SIG[%d]=", i);
        for (unsigned long long j = 0; j < out_sn; j++) printf("%02X", sn[j]);
        putchar('\n');
    }
    free(sn);
    free(sk);
    free(pk);
    return 0;
}
