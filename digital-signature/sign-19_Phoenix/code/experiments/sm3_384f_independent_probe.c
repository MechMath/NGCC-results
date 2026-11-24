#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "api.h"

static void print_hex(const char *label, const unsigned char *p, size_t n)
{
    size_t i;

    printf("%s=", label);
    for (i = 0; i < n; i++) {
        printf("%02x", p[i]);
    }
    putchar('\n');
}

int main(int argc, char **argv)
{
    const char *out_path = argc > 1 ? argv[1] : NULL;
    const char *verify_path = argc > 2 ? argv[2] : NULL;
    const char *seed_mode = getenv("PROBE_SEED_MODE");
    unsigned char seed[CRYPTO_SEEDBYTES];
    unsigned char msg[32];
    unsigned char *pk = calloc(CRYPTO_PUBLICKEYBYTES, 1);
    unsigned char *sk = calloc(CRYPTO_SECRETKEYBYTES, 1);
    unsigned char *sig = calloc(CRYPTO_BYTES, 1);
    unsigned char *sig_other = NULL;
    unsigned char *pk_other = calloc(CRYPTO_PUBLICKEYBYTES, 1);
    size_t siglen = 0, tfors_len = 0, sig_other_len = 0;
    int rc;
    size_t i;
    FILE *f;

    if (pk == NULL || sk == NULL || sig == NULL || pk_other == NULL) {
        return 2;
    }

    for (i = 0; i < sizeof(seed); i++) {
        if (seed_mode != NULL && strcmp(seed_mode, "zero") == 0) {
            seed[i] = 0x00;
        } else if (seed_mode != NULL && strcmp(seed_mode, "ff") == 0) {
            seed[i] = 0xff;
        } else {
            seed[i] = (unsigned char)(0x5a ^ i);
        }
    }
    for (i = 0; i < sizeof(msg); i++) {
        msg[i] = (unsigned char)(0xa5 ^ (3 * i));
    }

    printf("CRYPTO_SEEDBYTES=%llu\n",
           (unsigned long long)CRYPTO_SEEDBYTES);
    printf("CRYPTO_PUBLICKEYBYTES=%llu\n",
           (unsigned long long)CRYPTO_PUBLICKEYBYTES);
    printf("CRYPTO_BYTES=%llu\n", (unsigned long long)CRYPTO_BYTES);
    print_hex("seed", seed, sizeof(seed));
    print_hex("message", msg, sizeof(msg));

    if (verify_path != NULL) {
        long n;
        f = fopen(verify_path, "rb");
        if (f == NULL) {
            perror("fopen verify_path");
            return 2;
        }
        if (fseek(f, 0, SEEK_END) != 0 || (n = ftell(f)) < 0 ||
            fseek(f, 0, SEEK_SET) != 0) {
            return 2;
        }
        sig_other = malloc((size_t)n);
        if (sig_other == NULL || fread(sig_other, 1, (size_t)n, f) != (size_t)n) {
            return 2;
        }
        fclose(f);
        sig_other_len = (size_t)n;
        if (fopen(verify_path, "rb") == NULL) {
            return 2;
        }
    }

    rc = crypto_sign_seed_keypair(pk, sk, seed);
    printf("keypair_rc=%d\n", rc);
    print_hex("public_seed", pk, CRYPTO_PUBLICKEYBYTES / 2);
    print_hex("public_root", pk + CRYPTO_PUBLICKEYBYTES / 2,
              CRYPTO_PUBLICKEYBYTES / 2);

    if (verify_path != NULL) {
        /* The input contains [pk || siglen_le64 || signature]. */
        if (sig_other_len < CRYPTO_PUBLICKEYBYTES + 8) {
            return 2;
        }
        memcpy(pk_other, sig_other, CRYPTO_PUBLICKEYBYTES);
        memmove(sig_other, sig_other + CRYPTO_PUBLICKEYBYTES + 8,
                sig_other_len - CRYPTO_PUBLICKEYBYTES - 8);
        sig_other_len -= CRYPTO_PUBLICKEYBYTES + 8;
        rc = crypto_sign_verify(sig_other, sig_other_len, msg, sizeof(msg),
                                pk_other);
        printf("cross_verify_rc=%d\n", rc);
        free(sig_other);
        free(pk_other);
        free(sig);
        free(sk);
        free(pk);
        return 0;
    }

    rc = crypto_sign_signature(sig, &siglen, &tfors_len, msg, sizeof(msg), sk);
    printf("sign_rc=%d\n", rc);
    printf("signature_len=%zu\n", siglen);
    printf("tfors_len=%zu\n", tfors_len);
    rc = crypto_sign_verify(sig, siglen, msg, sizeof(msg), pk);
    printf("self_verify_rc=%d\n", rc);

    if (out_path != NULL) {
        uint64_t n = (uint64_t)siglen;
        f = fopen(out_path, "wb");
        if (f == NULL) {
            perror("fopen out_path");
            return 2;
        }
        if (fwrite(pk, 1, CRYPTO_PUBLICKEYBYTES, f) != CRYPTO_PUBLICKEYBYTES ||
            fwrite(&n, 1, sizeof(n), f) != sizeof(n) ||
            fwrite(sig, 1, siglen, f) != siglen) {
            return 2;
        }
        fclose(f);
        printf("witness_path=%s\n", out_path);
    }

    free(sig);
    free(sk);
    free(pk);
    return rc == 0 ? 0 : 1;
}
