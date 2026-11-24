#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "KEM_AlgorithmInstance.h"
#include "drng.h"
#include "loong_parameters.h"
#include "parsing.h"

DRNG_ctx drng_algorithm;

static unsigned char *read_file(const char *path, size_t expected)
{
    FILE *f = fopen(path, "rb");
    unsigned char *p;
    size_t got;
    if (!f) return NULL;
    p = malloc(expected);
    if (!p) {
        fclose(f);
        return NULL;
    }
    got = fread(p, 1, expected, f);
    if (got != expected || fgetc(f) != EOF) {
        fclose(f);
        free(p);
        return NULL;
    }
    fclose(f);
    return p;
}

int main(int argc, char **argv)
{
    unsigned char *pk = read_file("experiments/attack-public-pk.bin", LOONG_PK_BYTES);
    unsigned char *ct = read_file("experiments/attack-public-ct.bin", LOONG_CT_BYTES);
    unsigned char *expected = read_file("experiments/attack-expected-ss.bin", LOONG_SS_BYTES);
    const char *x_path = argc > 1 ? argv[1] : "experiments/attack-recovered-x.bin";
    unsigned char *x = read_file(x_path, LOONG_X_OR_S_BYTES);
    unsigned char *forged = calloc(LOONG_SK_BYTES, 1);
    unsigned char ss[LOONG_SS_BYTES];
    unsigned long long ss_len = LOONG_SS_BYTES;
    int rc;
    int ok;
    FILE *f;

    if (!pk || !ct || !expected || !x || !forged) return 2;
    memcpy(forged + LOONG_SK_SEED_OFFSET, pk + LOONG_PK_SEED_OFFSET,
           LOONG_PK_SEED_BYTES);
    memcpy(forged + LOONG_SK_X_OFFSET, x, LOONG_X_OR_S_BYTES);
    memcpy(forged + LOONG_SK_PK_OFFSET, pk, LOONG_PK_BYTES);
    /* xi is absent from the public key and is not needed for a valid ciphertext. */
    memset(forged + LOONG_SK_XI_OFFSET, 0, LOONG_XI_BYTES);

    rc = kem_dec(forged, LOONG_SK_BYTES, ct, LOONG_CT_BYTES, ss, &ss_len);
    ok = rc == 0 && ss_len == LOONG_SS_BYTES &&
         memcmp(ss, expected, LOONG_SS_BYTES) == 0;
    printf("forged_secret_decapsulation ok=%d rc=%d ss_len=%llu "
           "shared_secret_equals_encapsulation=%d\n",
           ok, rc, ss_len,
           memcmp(ss, expected, LOONG_SS_BYTES) == 0);
    f = fopen("experiments/attack-decapsulated-ss.bin", "wb");
    if (!f || fwrite(ss, 1, LOONG_SS_BYTES, f) != LOONG_SS_BYTES) return 3;
    fclose(f);
    free(forged);
    free(x);
    free(expected);
    free(ct);
    free(pk);
    return ok ? 0 : 1;
}
