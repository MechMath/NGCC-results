#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "SIG_AlgorithmInstance.h"
#include "api.h"

static unsigned char *read_file(const char *path, size_t *len) {
    FILE *f = fopen(path, "rb");
    unsigned char *buf;
    long n;

    if (f == NULL) {
        perror("fopen");
        exit(2);
    }
    if (fseek(f, 0, SEEK_END) != 0 || (n = ftell(f)) < 0 ||
        fseek(f, 0, SEEK_SET) != 0) {
        perror("fseek");
        exit(2);
    }
    buf = malloc((size_t)n);
    if (buf == NULL || fread(buf, 1, (size_t)n, f) != (size_t)n) {
        perror("read");
        exit(2);
    }
    fclose(f);
    *len = (size_t)n;
    return buf;
}

static int verify_parts(const unsigned char *pk, const unsigned char *m,
                        size_t mlen, const unsigned char *sn,
                        size_t snlen) {
    return sig_verify((unsigned char *)pk, CRYPTO_PUBLICKEYBYTES,
                      (unsigned char *)sn, (unsigned long long)snlen,
                      (unsigned char *)m, (unsigned long long)mlen);
}

int main(int argc, char **argv) {
    unsigned char *pk, *msg, *sig, *shifted, *whole, *bad_sig, *bad_msg;
    size_t pklen, mlen, siglen, prefix;
    int exact, mutated, shifted_prefix, shifted_empty, arbitrary;

    if (argc != 5) {
        fprintf(stderr, "usage: %s PK MSG SIG PREFIX_LEN\n", argv[0]);
        return 2;
    }

    pk = read_file(argv[1], &pklen);
    msg = read_file(argv[2], &mlen);
    sig = read_file(argv[3], &siglen);
    prefix = (size_t)strtoul(argv[4], NULL, 10);

    if (pklen != CRYPTO_PUBLICKEYBYTES || siglen != CRYPTO_BYTES ||
        prefix >= mlen) {
        fprintf(stderr,
                "bad sizes: pk=%zu/%llu sig=%zu/%d prefix=%zu msg=%zu\n",
                pklen, CRYPTO_PUBLICKEYBYTES, siglen, CRYPTO_BYTES,
                prefix, mlen);
        return 2;
    }

    exact = verify_parts(pk, msg, mlen, sig, siglen);

    bad_sig = malloc(siglen);
    memcpy(bad_sig, sig, siglen);
    bad_sig[0] ^= 1;
    mutated = verify_parts(pk, msg, mlen, bad_sig, siglen);

    shifted = malloc((mlen - prefix) + siglen);
    memcpy(shifted, msg + prefix, mlen - prefix);
    memcpy(shifted + (mlen - prefix), sig, siglen);
    shifted_prefix = verify_parts(pk, msg, prefix, shifted,
                                  (mlen - prefix) + siglen);

    whole = malloc(mlen + siglen);
    memcpy(whole, msg, mlen);
    memcpy(whole + mlen, sig, siglen);
    shifted_empty = verify_parts(pk, msg, 0, whole, mlen + siglen);

    bad_msg = malloc(mlen);
    memcpy(bad_msg, msg, mlen);
    bad_msg[prefix] ^= 1;
    arbitrary = verify_parts(pk, bad_msg, mlen, sig, siglen);

    printf("exact_valid=%d\n", exact);
    printf("mutated_signature=%d\n", mutated);
    printf("shifted_prefix_length=%zu verification=%d\n",
           prefix, shifted_prefix);
    printf("shifted_empty_message=%d\n", shifted_empty);
    printf("arbitrary_message_change=%d\n", arbitrary);

    free(pk);
    free(msg);
    free(sig);
    free(shifted);
    free(whole);
    free(bad_sig);
    free(bad_msg);
    return (exact == 0 && mutated != 0 && shifted_prefix == 0) ? 0 : 1;
}
