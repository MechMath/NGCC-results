#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "SIG_AlgorithmInstance.h"
#include "drng.h"

/*
 * The adapter source requires this definition, but the public SIG header
 * neither declares the symbol nor supplies an initialization API.  This
 * consumer therefore uses the source-internal DRNG header and relies on the
 * zero-initialized static storage of drng_algorithm.
 */
DRNG_ctx drng_algorithm;

static int write_file(const char *path, const unsigned char *p, size_t n)
{
    FILE *f = fopen(path, "wb");
    if (!f)
        return -1;
    if (fwrite(p, 1, n, f) != n) {
        fclose(f);
        return -1;
    }
    return fclose(f);
}

int main(void)
{
    unsigned long long pk_len = sig_get_pk_len_bytes();
    unsigned long long sk_len = sig_get_sk_len_bytes();
    unsigned long long sn_len = sig_get_sn_len_bytes();
    unsigned char *pk = calloc((size_t)pk_len, 1);
    unsigned char *sk = calloc((size_t)sk_len, 1);
    unsigned char *sn = calloc((size_t)sn_len, 1);
    unsigned char msg[8] = {'z','e','r','o','-','d','r','g'};
    int key_rc, sign_rc, verify_rc;

    if (!pk || !sk || !sn)
        return 100;
#ifdef CONTROL_INIT
    {
        unsigned char seed[64];
        size_t i;
        for (i = 0; i < sizeof(seed); i++)
            seed[i] = (unsigned char)(i * 17u + 3u);
        if (init_random_number(&drng_algorithm, seed, sizeof(seed)) != 0)
            return 102;
    }
#endif
    key_rc = sig_keygen(pk, &pk_len, sk, &sk_len);
    sign_rc = sig_sign(sk, sk_len, msg, sizeof(msg), sn, &sn_len);
    verify_rc = sig_verify(pk, pk_len, sn, sn_len, msg, sizeof(msg));
    printf("keygen=%d sign=%d verify=%d pk_len=%llu sk_len=%llu sn_len=%llu\n",
           key_rc, sign_rc, verify_rc, pk_len, sk_len, sn_len);

    if ((key_rc == 0) &&
        (write_file("pk.bin", pk, (size_t)pk_len) ||
         write_file("sk.bin", sk, (size_t)sk_len) ||
         write_file("sn.bin", sn, (size_t)sn_len)))
        return 101;
    free(sn);
    free(sk);
    free(pk);
    return (key_rc == 0 && sign_rc == 0 && verify_rc == 0) ? 0 : 1;
}
