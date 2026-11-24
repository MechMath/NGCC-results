#include <stddef.h>
#include <stdlib.h>
#include "SIG_AlgorithmInstance.h"

/*
 * This translation unit uses only the declared public SIG adapter header.
 * It intentionally contains no knowledge of the adapter's private DRNG.
 */
int main(void)
{
    unsigned long long pk_len = sig_get_pk_len_bytes();
    unsigned long long sk_len = sig_get_sk_len_bytes();
    unsigned long long sn_len = sig_get_sn_len_bytes();
    unsigned char *pk = calloc((size_t)pk_len, 1);
    unsigned char *sk = calloc((size_t)sk_len, 1);
    unsigned char *sn = calloc((size_t)sn_len, 1);
    unsigned char msg[1] = {0x42};
    int rc;

    if (!pk || !sk || !sn)
        return 100;
    rc = sig_keygen(pk, &pk_len, sk, &sk_len);
    if (rc == 0)
        rc = sig_sign(sk, sk_len, msg, sizeof(msg), sn, &sn_len);
    free(sn);
    free(sk);
    free(pk);
    return rc == 0 ? 0 : 1;
}
