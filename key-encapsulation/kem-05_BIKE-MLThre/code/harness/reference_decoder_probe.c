#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "types.h"
#include "conversions.h"
#include "decode_ml.h"
#include "ntl.h"

#ifndef HARNESS_SECURITY_BITS
#define HARNESS_SECURITY_BITS 0
#endif

typedef struct {
    const char *name;
    int kind;
    unsigned char mask;
} mutation_t;

enum { OFF_FIRST, OFF_MID, OFF_LAST, OFF_C1_FIRST, OFF_C1_MID, OFF_C1_LAST,
       ZERO_C0, ZERO_C1, FF_C1, ZERO_ALL, PAIR, ZERO_MID, FF_C1_MID, TWO_BITS };

static const mutation_t MUTATIONS[] = {
    {"baseline",           -1,   0x00},
    {"c0_first_bit",       OFF_FIRST, 0x01},
    {"c0_mid_bit",         OFF_MID, 0x01},
    {"c0_last_bit",        OFF_LAST, 0x01},
    {"c1_first_bit",       OFF_C1_FIRST, 0x01},
    {"c1_mid_bit",         OFF_C1_MID, 0x01},
    {"c1_last_bit",        OFF_C1_LAST, 0x01},
    {"c0_mid_zero_byte",   ZERO_MID, 0x00},
    {"c1_mid_ff_byte",     FF_C1_MID, 0x00},
    {"c0_two_bits",        TWO_BITS, 0x81},
    {"c0_c1_pair",         PAIR, 0x01},
    {"c0_all_zero",        ZERO_C0, 0x00},
    {"c1_all_zero",        ZERO_C1, 0x00},
    {"c1_all_ff",          FF_C1, 0x00},
    {"ct_all_zero",        ZERO_ALL, 0x00},
};

static size_t weight(const uint8_t *bits, size_t n)
{
    size_t result = 0;
    for(size_t i = 0; i < n; ++i) {
        result += bits[i] != 0;
    }
    return result;
}

static unsigned char *read_blob(const char *path, size_t expected)
{
    FILE *f = fopen(path, "rb");
    unsigned char *buf;

    if(f == NULL || fseek(f, 0, SEEK_END) != 0 ||
       (size_t)ftell(f) != expected || fseek(f, 0, SEEK_SET) != 0) {
        fprintf(stderr, "invalid input %s (expected %zu bytes)\n", path, expected);
        if(f != NULL) fclose(f);
        return NULL;
    }
    buf = malloc(expected);
    if(buf == NULL || fread(buf, 1, expected, f) != expected) {
        free(buf);
        fclose(f);
        return NULL;
    }
    fclose(f);
    return buf;
}

static int apply_mutation(uint8_t *ct, const mutation_t *m)
{
    const size_t rsize = sizeof(((ct_t *)0)->val0);
    const size_t ell = sizeof(((ct_t *)0)->val1);

    switch(m->kind) {
        case -1: break;
        case OFF_FIRST: ct[0] ^= m->mask; break;
        case OFF_MID: ct[rsize / 2U] ^= m->mask; break;
        case OFF_LAST: ct[rsize - 1U] ^= m->mask; break;
        case OFF_C1_FIRST: ct[rsize] ^= m->mask; break;
        case OFF_C1_MID: ct[rsize + ell / 2U] ^= m->mask; break;
        case OFF_C1_LAST: ct[rsize + ell - 1U] ^= m->mask; break;
        case ZERO_MID: ct[rsize / 2U] = 0; break;
        case FF_C1_MID: ct[rsize + ell / 2U] = 0xff; break;
        case TWO_BITS: ct[rsize / 2U] ^= m->mask; break;
        case PAIR: ct[0] ^= m->mask; ct[rsize] ^= m->mask; break;
        case ZERO_C0: memset(ct, 0, rsize); break;
        case ZERO_C1: memset(ct + rsize, 0, ell); break;
        case FF_C1: memset(ct + rsize, 0xff, ell); break;
        case ZERO_ALL: memset(ct, 0, rsize + ell); break;
        default: return -1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    sk_t sk;
    ct_t ct_orig;
    ct_t ct;
    syndrome_t syndrome;
    uint8_t e[R_BITS * 2];
    uint8_t s0[R_SIZE];
    uint8_t s_bits[R_BITS];
    uint32_t h0[DV];
    uint32_t h1[DV];
    unsigned char *sk_bytes;
    unsigned char *ct_bytes;
    const char *out_path;
    FILE *out;

    if(argc != 4) {
        fprintf(stderr, "usage: %s SK CT OUTPUT.tsv\n", argv[0]);
        return 2;
    }
    sk_bytes = read_blob(argv[1], sizeof(sk));
    ct_bytes = read_blob(argv[2], sizeof(ct_orig));
    if(sk_bytes == NULL || ct_bytes == NULL) {
        return 2;
    }
    memcpy(&sk, sk_bytes, sizeof(sk));
    memcpy(&ct_orig, ct_bytes, sizeof(ct_orig));
    free(sk_bytes);
    free(ct_bytes);
    convert2compact(h0, sk.val0);
    convert2compact(h1, sk.val1);

    out_path = argv[3];
    out = fopen(out_path, "w");
    if(out == NULL) {
        fprintf(stderr, "fopen(%s): %s\n", out_path, strerror(errno));
        return 2;
    }
    fprintf(out,
            "security_bits\tprobe\tdecoder_rc\tinitial_syndrome_weight\t"
            "final_syndrome_weight\tguessed_error_weight\n");

    for(size_t i = 0; i < sizeof(MUTATIONS) / sizeof(MUTATIONS[0]); ++i) {
        uint32_t initial_weight;
        uint32_t final_weight;
        int rc;

        ct = ct_orig;
        if(apply_mutation(ct.raw, &MUTATIONS[i]) != 0) {
            continue;
        }
        memset(s0, 0, sizeof(s0));
        memset(s_bits, 0, sizeof(s_bits));
        memset(syndrome.raw, 0, sizeof(syndrome.raw));
        memset(e, 0, sizeof(e));
        ntl_mod_mul(s0, sk.val0, ct.val0);
        convertByteToBinary(s_bits, s0, R_BITS);
        transpose(syndrome.raw, s_bits);
        initial_weight = (uint32_t)weight(syndrome.raw, R_BITS);
        rc = BGF_decoder(e, syndrome.raw, h0, h1);
        final_weight = (uint32_t)weight(syndrome.raw, R_BITS);
        fprintf(out, "%d\t%s\t%d\t%u\t%u\t%zu\n",
                HARNESS_SECURITY_BITS, MUTATIONS[i].name, rc,
                initial_weight, final_weight, weight(e, R_BITS * 2));
        fflush(out);
    }
    fclose(out);
    return 0;
}
