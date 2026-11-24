#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "SIG_AlgorithmInstance.h"

static void hex(FILE *out, const unsigned char *p, size_t n) {
    for (size_t i = 0; i < n; ++i)
        fprintf(out, "%02x", p[i]);
}

int main(void) {
    const unsigned long long pkcap = sig_get_pk_len_bytes();
    const unsigned long long skcap = sig_get_sk_len_bytes();
    unsigned char *pk1 = malloc(pkcap), *pk2 = malloc(pkcap), *pk3 = malloc(pkcap);
    unsigned char *sk1 = malloc(skcap), *sk2 = malloc(skcap), *sk3 = malloc(skcap);
    unsigned long long pk1n = pkcap, pk2n = pkcap, sk1n = skcap, sk2n = skcap;
    unsigned long long pk3n = pkcap, sk3n = skcap;
    const unsigned char nonzero_seed[32] = {1};
    if (!pk1 || !pk2 || !pk3 || !sk1 || !sk2 || !sk3) return 2;

    /* Leave the KAT hook unset, as in the normal NGCC API path. */
    galas_set_kat_seed(NULL, 0);
    if (sig_keygen(pk1, &pk1n, sk1, &sk1n) != 0) return 3;
    if (sig_keygen(pk2, &pk2n, sk2, &sk2n) != 0) return 4;
    galas_set_kat_seed(nonzero_seed, sizeof(nonzero_seed));
    if (sig_keygen(pk3, &pk3n, sk3, &sk3n) != 0) return 5;

    printf("pk_equal=%d sk_equal=%d pk_len=%llu sk_len=%llu nonzero_seed_changes_pk=%d\n",
           pk1n == pk2n && memcmp(pk1, pk2, pk1n) == 0,
           sk1n == sk2n && memcmp(sk1, sk2, sk1n) == 0,
           pk1n, sk1n,
           pk1n != pk3n || memcmp(pk1, pk3, pk1n) != 0);
    fputs("pk=", stdout); hex(stdout, pk1, pk1n); fputc('\n', stdout);
    fputs("sk=", stdout); hex(stdout, sk1, sk1n); fputc('\n', stdout);

    free(pk1); free(pk2); free(pk3); free(sk1); free(sk2); free(sk3);
    return 0;
}
