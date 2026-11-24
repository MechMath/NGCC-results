#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "api.h"
#include "params.h"

#define MAGIC "SM3IOP01"
#define MSG_BYTES 32

typedef struct {
    unsigned long long siglen;
    unsigned char msg[MSG_BYTES];
    unsigned char pk[SPX_PK_BYTES];
    unsigned char *sig;
} witness;

static int save(const char *path, const witness *w)
{
    FILE *f = fopen(path, "wb");
    if (f == NULL) {
        perror(path);
        return -1;
    }
    int ok = fwrite(MAGIC, 1, 8, f) == 8 &&
             fwrite(&w->siglen, sizeof(w->siglen), 1, f) == 1 &&
             fwrite(w->msg, 1, sizeof(w->msg), f) == sizeof(w->msg) &&
             fwrite(w->pk, 1, sizeof(w->pk), f) == sizeof(w->pk) &&
             fwrite(w->sig, 1, (size_t)w->siglen, f) == (size_t)w->siglen;
    fclose(f);
    return ok ? 0 : -1;
}

static int load(const char *path, witness *w)
{
    unsigned char magic[8];
    FILE *f = fopen(path, "rb");
    if (f == NULL) {
        perror(path);
        return -1;
    }
    int ok = fread(magic, 1, 8, f) == 8 &&
             memcmp(magic, MAGIC, 8) == 0 &&
             fread(&w->siglen, sizeof(w->siglen), 1, f) == 1 &&
             fread(w->msg, 1, sizeof(w->msg), f) == sizeof(w->msg) &&
             fread(w->pk, 1, sizeof(w->pk), f) == sizeof(w->pk);
    if (ok) {
        w->sig = malloc((size_t)w->siglen);
        ok = w->sig != NULL &&
             fread(w->sig, 1, (size_t)w->siglen, f) == (size_t)w->siglen;
    }
    fclose(f);
    return ok ? 0 : -1;
}

static void print_hex(const char *label, const unsigned char *p, size_t n)
{
    printf("%s=", label);
    for (size_t i = 0; i < n; i++) {
        printf("%02x", p[i]);
    }
    putchar('\n');
}

#ifdef WRITE_WITNESS
int main(int argc, char **argv)
{
    if (argc != 2) {
        return 2;
    }
    witness w = {0};
    unsigned char seed[CRYPTO_SEEDBYTES];
    unsigned char sk[SPX_SK_BYTES];
    unsigned char sig[CRYPTO_BYTES];
    size_t siglen = 0;
    size_t tfors_len = 0;

    for (size_t i = 0; i < sizeof(seed); i++) {
        seed[i] = (unsigned char)(0x5aU ^ i);
    }
    memset(w.msg, 0, sizeof(w.msg));
    memcpy(w.msg, "SM3-384f cross-backend", 22);
    if (crypto_sign_seed_keypair(w.pk, sk, seed) != 0) {
        return 3;
    }
    if (crypto_sign_signature(sig, &siglen, &tfors_len,
                              w.msg, sizeof(w.msg), sk) != 0) {
        return 4;
    }
    w.siglen = siglen;
    w.sig = sig;
    print_hex("pk", w.pk, sizeof(w.pk));
    printf("siglen=%zu tfors_len=%zu\n", siglen, tfors_len);
    return save(argv[1], &w) == 0 ? 0 : 5;
}
#else
int main(int argc, char **argv)
{
    if (argc != 2) {
        return 2;
    }
    witness w = {0};
    if (load(argv[1], &w) != 0) {
        return 3;
    }
    print_hex("pk", w.pk, sizeof(w.pk));
    int rc = crypto_sign_verify(w.sig, (size_t)w.siglen,
                                w.msg, sizeof(w.msg), w.pk);
    printf("siglen=%llu verify_rc=%d\n", w.siglen, rc);
    free(w.sig);
    return rc == 0 ? 0 : 1;
}
#endif
