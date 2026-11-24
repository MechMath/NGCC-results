#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

#include "api.h"
#include "drng.h"
#include "SIG_AlgorithmInstance.h"

DRNG_ctx drng_algorithm;

int main(int argc, char **argv)
{
    const char *mode = argc > 1 ? argv[1] : "short";
    uint8_t *pk;
    uint8_t *sk;
    uint8_t *sig;
    uint8_t msg[32] = {0};
    unsigned char seed[55] = {0};
    unsigned long long pk_len = 0;
    unsigned long long sk_len = 0;
    unsigned long long sig_len = 0;
    unsigned long long declared_pk_len;
    int guard_mapping = 0;
    int rc;

    pk = calloc(CRYPTO_PUBLICKEYBYTES, 1);
    sk = calloc(CRYPTO_SECRETKEYBYTES, 1);
    sig = calloc(CRYPTO_BYTES, 1);
    if (pk == NULL || sk == NULL || sig == NULL)
        return 9;

    if (init_random_number(&drng_algorithm, seed, sizeof seed) != 0)
        return 10;
    if (sig_keygen(pk, &pk_len, sk, &sk_len) != 0)
        return 11;
    if (sig_sign(sk, sk_len, msg, sizeof msg, sig, &sig_len) != 0)
        return 12;

    if (strcmp(mode, "altered_message") == 0)
        msg[0] ^= 1;
    if (strcmp(mode, "altered_signature") == 0)
        sig[0] ^= 1;

    declared_pk_len = pk_len;
    if (strcmp(mode, "short_pk") == 0) {
        uint8_t *short_pk = calloc(1, 1);
        if (short_pk == NULL)
            return 13;
        free(pk);
        pk = short_pk;
        declared_pk_len = 1;
    }
    if (strcmp(mode, "short_pk_guard") == 0) {
        const size_t page = (size_t)sysconf(_SC_PAGESIZE);
        uint8_t *mapping = mmap(NULL, 2 * page, PROT_READ | PROT_WRITE,
                                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (mapping == MAP_FAILED)
            return 14;
        if (mprotect(mapping + page, page, PROT_NONE) != 0)
            return 15;
        free(pk);
        pk = mapping + page - 1;
        declared_pk_len = 1;
        guard_mapping = 1;
    }
    if (strcmp(mode, "malformed_full_pk") == 0)
        memset(pk, 0xff, CRYPTO_PUBLICKEYBYTES);

    fprintf(stderr,
            "case=%s generated_pk_len=%llu declared_pk_len=%llu sk_len=%llu sn_len=%llu\n",
            mode,
            pk_len,
            declared_pk_len,
            sk_len,
            sig_len);
    fflush(stderr);

    rc = sig_verify(pk, declared_pk_len, sig, sig_len, msg, sizeof msg);
    fprintf(stderr, "sig_verify_rc=%d\n", rc);
    free(sig);
    free(sk);
    if (!guard_mapping)
        free(pk);
    return 0;
}
