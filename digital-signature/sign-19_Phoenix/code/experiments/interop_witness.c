#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "api.h"
#include "params.h"

#define MAGIC "PHXWIT01"
#define MSG_BYTES 32

typedef struct {
    unsigned long long siglen;
    unsigned long long tfors_len;
    unsigned char msg[MSG_BYTES];
    unsigned char pk[SPX_PK_BYTES];
    unsigned char *sig;
} witness;

static void fill_seed(unsigned char seed[CRYPTO_SEEDBYTES]) {
    for (size_t i = 0; i < CRYPTO_SEEDBYTES; i++) {
        seed[i] = (unsigned char)(0x5aU ^ (unsigned char)i);
    }
}

static void fill_message(unsigned char msg[MSG_BYTES], unsigned long t) {
    memset(msg, 0, MSG_BYTES);
    msg[0] = (unsigned char)t;
    msg[1] = (unsigned char)(t >> 8);
    msg[2] = (unsigned char)(t >> 16);
    msg[3] = (unsigned char)(t >> 24);
}

static int write_witness(const char *path, const witness *w) {
    FILE *f = fopen(path, "wb");
    if (f == NULL) {
        perror(path);
        return -1;
    }
    if (fwrite(MAGIC, 1, 8, f) != 8 ||
        fwrite(&w->siglen, sizeof(w->siglen), 1, f) != 1 ||
        fwrite(&w->tfors_len, sizeof(w->tfors_len), 1, f) != 1 ||
        fwrite(w->msg, 1, sizeof(w->msg), f) != sizeof(w->msg) ||
        fwrite(w->pk, 1, sizeof(w->pk), f) != sizeof(w->pk) ||
        fwrite(w->sig, 1, (size_t)w->siglen, f) != (size_t)w->siglen) {
        fclose(f);
        return -1;
    }
    return fclose(f);
}

static int read_witness(const char *path, witness *w) {
    unsigned char magic[8];
    FILE *f = fopen(path, "rb");
    if (f == NULL) {
        perror(path);
        return -1;
    }
    if (fread(magic, 1, sizeof(magic), f) != sizeof(magic) ||
        memcmp(magic, MAGIC, sizeof(magic)) != 0 ||
        fread(&w->siglen, sizeof(w->siglen), 1, f) != 1 ||
        fread(&w->tfors_len, sizeof(w->tfors_len), 1, f) != 1 ||
        fread(w->msg, 1, sizeof(w->msg), f) != sizeof(w->msg) ||
        fread(w->pk, 1, sizeof(w->pk), f) != sizeof(w->pk)) {
        fclose(f);
        return -1;
    }
    w->sig = malloc((size_t)w->siglen);
    if (w->sig == NULL ||
        fread(w->sig, 1, (size_t)w->siglen, f) != (size_t)w->siglen) {
        fclose(f);
        free(w->sig);
        return -1;
    }
    return fclose(f);
}

#ifdef WRITE_WITNESS
int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "usage: %s SPECIAL_PATH CONTROL_PATH\n", argv[0]);
        return 2;
    }

    const unsigned long long special_tfors = 5376ULL;
    const unsigned long long reference_cap = 5372ULL;
    unsigned char seed[CRYPTO_SEEDBYTES];
    unsigned char sk[SPX_SK_BYTES];
    witness special = {0}, control = {0};
    int have_special = 0, have_control = 0;

    fill_seed(seed);
    if (crypto_sign_seed_keypair(special.pk, sk, seed) != 0) {
        return 3;
    }
    memcpy(control.pk, special.pk, sizeof(control.pk));
    special.sig = malloc(CRYPTO_BYTES);
    control.sig = malloc(CRYPTO_BYTES);
    if (special.sig == NULL || control.sig == NULL) {
        return 4;
    }

    for (unsigned long t = 0; t < 1000 && !(have_special && have_control); t++) {
        unsigned char msg[MSG_BYTES];
        unsigned char sig[CRYPTO_BYTES];
        size_t siglen = 0;
        size_t tfors_len = 0;
        fill_message(msg, t);
        int rc = crypto_sign_signature(sig, &siglen, &tfors_len, msg,
                                       sizeof(msg), sk);
        printf("trial=%lu rc=%d siglen=%zu tfors_len=%zu\n",
               t, rc, siglen, tfors_len);
        if (rc != 0) {
            continue;
        }
        if (!have_special && tfors_len == special_tfors) {
            special.siglen = siglen;
            special.tfors_len = tfors_len;
            memcpy(special.msg, msg, sizeof(msg));
            memcpy(special.sig, sig, siglen);
            have_special = 1;
        }
        if (!have_control && tfors_len <= reference_cap) {
            control.siglen = siglen;
            control.tfors_len = tfors_len;
            memcpy(control.msg, msg, sizeof(msg));
            memcpy(control.sig, sig, siglen);
            have_control = 1;
        }
    }

    if (!have_special || !have_control) {
        fprintf(stderr, "failed to collect witnesses: special=%d control=%d\n",
                have_special, have_control);
        return 5;
    }
    if (write_witness(argv[1], &special) != 0 ||
        write_witness(argv[2], &control) != 0) {
        return 6;
    }
    printf("wrote special=%s control=%s\n", argv[1], argv[2]);
    free(special.sig);
    free(control.sig);
    return 0;
}
#else
int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s WITNESS_PATH\n", argv[0]);
        return 2;
    }
    witness w = {0};
    if (read_witness(argv[1], &w) != 0) {
        return 3;
    }
    int rc = crypto_sign_verify(w.sig, (size_t)w.siglen, w.msg,
                                sizeof(w.msg), w.pk);
    printf("verify_path=%s siglen=%llu tfors_len=%llu verify_rc=%d\n",
           argv[1], w.siglen, w.tfors_len, rc);
    free(w.sig);
    return rc == 0 ? 0 : 1;
}
#endif
