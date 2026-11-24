#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "KEM_AlgorithmInstance.h"
#include "drng.h"
#include "loong_parameters.h"
#include "parsing.h"
#include "rbc_elt.h"

DRNG_ctx drng_algorithm;

int attack_export_generate_public_objects(rbc_elt *g, rbc_elt *h,
                                          const unsigned char *public_seed,
                                          unsigned long long public_seed_len_bytes);

static uint64_t elt_value(const rbc_elt *e)
{
    uint64_t v = 0;
    unsigned int i;
    for (i = 0; i < RBC_FIELD_M; i++) {
        v |= (uint64_t)rbc_elt_get_coefficient(e, i) << i;
    }
    return v;
}

static uint64_t packed_value(const unsigned char *p, size_t bit_offset)
{
    uint64_t v = 0;
    unsigned int i;
    for (i = 0; i < LOONG_M; i++) {
        size_t pos = bit_offset + i;
        unsigned int bit = (p[pos / 8] >> (7 - (pos % 8))) & 1U;
        v |= (uint64_t)bit << i;
    }
    return v;
}

static void unpack_value(rbc_elt *e, const unsigned char *p, size_t bit_offset)
{
    unsigned int i;
    rbc_elt_set_zero(e);
    for (i = 0; i < LOONG_M; i++) {
        size_t pos = bit_offset + i;
        unsigned int bit = (p[pos / 8] >> (7 - (pos % 8))) & 1U;
        rbc_elt_set_coefficient(e, i, bit);
    }
}

static void print_values(const char *name, const uint64_t *v, size_t n)
{
    size_t i;
    printf("%s", name);
    for (i = 0; i < n; i++) {
        printf(" %012llx", (unsigned long long)v[i]);
    }
    printf("\n");
}

static int write_file(const char *path, const void *data, size_t len)
{
    FILE *f = fopen(path, "wb");
    if (!f) return 0;
    if (fwrite(data, 1, len, f) != len) {
        fclose(f);
        return 0;
    }
    return fclose(f) == 0;
}

int main(int argc, char **argv)
{
    unsigned char seed[64];
    unsigned char *pk = calloc(LOONG_PK_BYTES, 1);
    unsigned char *sk = calloc(LOONG_SK_BYTES, 1);
    unsigned long long pk_len = LOONG_PK_BYTES;
    unsigned long long sk_len = LOONG_SK_BYTES;
    rbc_elt *g = calloc(LOONG_N1 * LOONG_N2, sizeof(*g));
    rbc_elt *h = calloc(LOONG_N * LOONG_N, sizeof(*h));
    uint64_t hv[LOONG_N * LOONG_N];
    uint64_t sv[LOONG_N * LOONG_N1];
    uint64_t xv[LOONG_N * LOONG_N1];
    uint64_t hvx[LOONG_N * LOONG_N1];
    uint64_t inferred_y[LOONG_N * LOONG_N1];
    unsigned char ct[LOONG_CT_BYTES];
    unsigned char ss[LOONG_SS_BYTES];
    unsigned long long ct_len = LOONG_CT_BYTES;
    unsigned long long ss_len = LOONG_SS_BYTES;
    size_t i;
    int rc;

    if (!pk || !sk || !g || !h) return 2;
    memset(seed, argc > 1 ? (unsigned char)strtoul(argv[1], NULL, 0) : 0x5a,
           sizeof(seed));
    init_random_number(&drng_algorithm, seed, sizeof(seed) * 8);
    rc = kem_keygen(pk, &pk_len, sk, &sk_len);
    if (rc != 0) return 3;
    rc = kem_enc(pk, pk_len, ss, &ss_len, ct, &ct_len);
    if (rc != 0) return 5;
    rc = attack_export_generate_public_objects(g, h, pk, LOONG_PK_SEED_BYTES);
    if (rc != 0) return 4;

    for (i = 0; i < LOONG_N * LOONG_N; i++) hv[i] = elt_value(&h[i]);
    for (i = 0; i < LOONG_N * LOONG_N1; i++) {
        sv[i] = packed_value(pk + LOONG_PK_S_OFFSET, i * LOONG_M);
        xv[i] = packed_value(sk + LOONG_SK_X_OFFSET, i * LOONG_M);
    }
    for (i = 0; i < LOONG_N; i++) {
        unsigned int j;
        for (j = 0; j < LOONG_N1; j++) {
            unsigned int k;
            rbc_elt acc;
            rbc_elt_set_zero(&acc);
            for (k = 0; k < LOONG_N; k++) {
                rbc_elt x;
                rbc_elt product;
                unpack_value(&x, sk + LOONG_SK_X_OFFSET, (k * LOONG_N1 + j) * LOONG_M);
                rbc_elt_mul(&product, &h[i * LOONG_N + k], &x);
                rbc_elt_add(&acc, &acc, &product);
            }
            hvx[i * LOONG_N1 + j] = elt_value(&acc);
            inferred_y[i * LOONG_N1 + j] = sv[i * LOONG_N1 + j] ^ hvx[i * LOONG_N1 + j];
        }
    }
    printf("META n=%d n1=%d m=%d seed_bytes=%d axy00=%d axy01=%d axy11=%d\n",
           LOONG_N, LOONG_N1, LOONG_M, LOONG_PK_SEED_BYTES,
           LOONG_AXY_00, LOONG_AXY_01, LOONG_AXY_11);
    print_values("H", hv, LOONG_N * LOONG_N);
    print_values("S", sv, LOONG_N * LOONG_N1);
    print_values("XTRUTH", xv, LOONG_N * LOONG_N1);
    print_values("HX_CTRUTH", hvx, LOONG_N * LOONG_N1);
    print_values("Y_INFERRED", inferred_y, LOONG_N * LOONG_N1);
    if (!write_file("experiments/attack-public-pk.bin", pk, LOONG_PK_BYTES) ||
        !write_file("experiments/attack-public-ct.bin", ct, LOONG_CT_BYTES) ||
        !write_file("experiments/attack-expected-ss.bin", ss, LOONG_SS_BYTES) ||
        !write_file("experiments/attack-truth-x.bin", sk + LOONG_SK_X_OFFSET,
                    LOONG_X_OR_S_BYTES)) {
        return 6;
    }
    free(h);
    free(g);
    free(sk);
    free(pk);
    return 0;
}
