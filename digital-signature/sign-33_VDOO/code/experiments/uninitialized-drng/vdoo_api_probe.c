#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "api.h"
#include "rng.h"

static unsigned char *read_file(const char *path, unsigned long long *len)
{
    FILE *f = fopen(path, "rb");
    unsigned char *buf;
    long n;

    if (!f) return NULL;
    if (fseek(f, 0, SEEK_END) != 0) return NULL;
    n = ftell(f);
    if (n < 0 || fseek(f, 0, SEEK_SET) != 0) return NULL;
    buf = malloc((size_t)n + 1);
    if (!buf) return NULL;
    if (fread(buf, 1, (size_t)n, f) != (size_t)n) {
        free(buf);
        fclose(f);
        return NULL;
    }
    fclose(f);
    *len = (unsigned long long)n;
    return buf;
}

static int write_file(const char *path, const unsigned char *buf,
                      unsigned long long len)
{
    FILE *f = fopen(path, "wb");
    int ok;

    if (!f) return -1;
    ok = fwrite(buf, 1, (size_t)len, f) == (size_t)len && fclose(f) == 0;
    return ok ? 0 : -1;
}

static int keygen(const char *pk_path, const char *sk_path,
                  const char *seed_path)
{
    unsigned char *pk = malloc(CRYPTO_PUBLICKEYBYTES);
    unsigned char *sk = malloc(CRYPTO_SECRETKEYBYTES);
    int r = 3;

    if (!pk || !sk) goto out;
    if (seed_path) {
        unsigned long long seed_len = 0;
        unsigned char *seed = read_file(seed_path, &seed_len);
        if (!seed) {
            fprintf(stderr, "could not read seed\n");
            r = 2;
            goto out;
        }
        init_randombytes(seed, seed_len);
        free(seed);
    }

    if (crypto_sign_keypair(pk, sk) != 0) goto out;
    if (write_file(pk_path, pk, CRYPTO_PUBLICKEYBYTES) != 0) {
        r = 4;
        goto out;
    }
    if (write_file(sk_path, sk, CRYPTO_SECRETKEYBYTES) != 0) {
        r = 5;
        goto out;
    }
    r = 0;
out:
    free(sk);
    free(pk);
    return r;
}

static int sign_file(const char *sk_path, const char *msg_path,
                     const char *sig_path)
{
    unsigned long long sk_len = 0, msg_len = 0, sm_len = 0;
    unsigned char *sk = read_file(sk_path, &sk_len);
    unsigned char *msg = read_file(msg_path, &msg_len);
    unsigned char *sm;
    int r;

    if (!sk || !msg || sk_len != CRYPTO_SECRETKEYBYTES) return 2;
    sm = malloc((size_t)(msg_len + CRYPTO_BYTES));
    if (!sm) return 3;
    r = crypto_sign(sm, &sm_len, msg, msg_len, sk);
    if (r == 0) {
        r = write_file(sig_path, sm + msg_len, CRYPTO_BYTES);
    }
    free(sm);
    free(msg);
    free(sk);
    return r;
}

static int verify_file(const char *pk_path, const char *msg_path,
                       const char *sig_path)
{
    unsigned long long pk_len = 0, msg_len = 0, sig_len = 0, out_len = 0;
    unsigned char *pk = read_file(pk_path, &pk_len);
    unsigned char *msg = read_file(msg_path, &msg_len);
    unsigned char *sig = read_file(sig_path, &sig_len);
    unsigned char *sm = NULL;
    int r = 2;

    if (!pk || !msg || !sig || pk_len != CRYPTO_PUBLICKEYBYTES ||
        sig_len != CRYPTO_BYTES)
        goto out;
    sm = malloc((size_t)(msg_len + sig_len));
    if (!sm) {
        r = 3;
        goto out;
    }
    memcpy(sm, msg, (size_t)msg_len);
    memcpy(sm + msg_len, sig, (size_t)sig_len);
    r = crypto_sign_open(NULL, &out_len, sm, msg_len + sig_len, pk);
out:
    free(sm);
    free(sig);
    free(msg);
    free(pk);
    return r;
}

int main(int argc, char **argv)
{
    if (argc == 4 && strcmp(argv[1], "keygen") == 0) {
        return keygen(argv[2], argv[3], NULL);
    }
    if (argc == 5 && strcmp(argv[1], "seeded-keygen") == 0) {
        return keygen(argv[2], argv[3], argv[4]);
    }
    if (argc == 5 && strcmp(argv[1], "sign") == 0) {
        return sign_file(argv[2], argv[3], argv[4]);
    }
    if (argc == 5 && strcmp(argv[1], "verify") == 0) {
        int r = verify_file(argv[2], argv[3], argv[4]);
        printf("verify=%d\n", r);
        return r == 0 ? 0 : 1;
    }
    fprintf(stderr,
            "usage: %s keygen PK SK | seeded-keygen PK SK SEED | "
            "sign SK MSG SIG | verify PK MSG SIG\n",
            argv[0]);
    return 2;
}
