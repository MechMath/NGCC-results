#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include <openssl/evp.h>

#include "KEM_AlgorithmInstance.h"
#include "drng.h"

#ifndef HARNESS_LABEL
#define HARNESS_LABEL "unknown"
#endif

#ifndef HARNESS_SECURITY_BITS
#define HARNESS_SECURITY_BITS 0
#endif

DRNG_ctx drng_algorithm;

typedef struct {
    const char *name;
    size_t offset_kind;
    unsigned char xor_mask;
    int operation;
} mutation_t;

enum {
    MUT_XOR = 1,
    MUT_ZERO_BYTE = 2,
    MUT_FF_BYTE = 3,
    MUT_SECOND_XOR = 4
};

/* Offsets 0..7 are resolved relative to ct_len and the final ss_len bytes.
 * This keeps the same probe names meaningful at every supported width. */
static const mutation_t MUTATIONS[] = {
    {"baseline",         0, 0x00, MUT_XOR},
    {"c0_first_bit",     1, 0x01, MUT_XOR},
    {"c0_mid_bit",       2, 0x01, MUT_XOR},
    {"c0_last_bit",      3, 0x01, MUT_XOR},
    {"c1_first_bit",     4, 0x01, MUT_XOR},
    {"c1_mid_bit",       5, 0x01, MUT_XOR},
    {"c1_last_bit",      6, 0x01, MUT_XOR},
    {"c0_mid_zero_byte", 2, 0x00, MUT_ZERO_BYTE},
    {"c1_mid_ff_byte",   5, 0x00, MUT_FF_BYTE},
    {"c0_two_bits",      2, 0x81, MUT_XOR},
    {"c0_c1_pair",       1, 0x01, MUT_SECOND_XOR},
    {"c0_all_zero",      8, 0x00, MUT_ZERO_BYTE},
    {"c1_all_zero",      9, 0x00, MUT_ZERO_BYTE},
    {"c1_all_ff",        9, 0x00, MUT_FF_BYTE},
    {"ct_all_zero",     10, 0x00, MUT_ZERO_BYTE},
};

static int ensure_dir(const char *path)
{
    return (mkdir(path, 0755) == 0 || errno == EEXIST) ? 0 : -1;
}

static unsigned char *read_blob(const char *path, size_t expected, size_t *actual)
{
    FILE *f = fopen(path, "rb");
    unsigned char *buf;

    if(f == NULL) {
        fprintf(stderr, "fopen(%s): %s\n", path, strerror(errno));
        return NULL;
    }
    if(fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return NULL;
    }
    *actual = (size_t)ftell(f);
    if(*actual != expected || fseek(f, 0, SEEK_SET) != 0) {
        fprintf(stderr, "%s: size %zu, expected %zu\n", path, *actual, expected);
        fclose(f);
        return NULL;
    }
    buf = malloc(expected);
    if(buf == NULL || fread(buf, 1, expected, f) != expected || fclose(f) != 0) {
        free(buf);
        return NULL;
    }
    return buf;
}

static void sha256_hex(const unsigned char *buf, size_t len, char out[65])
{
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;

    if(!EVP_Digest(buf, len, digest, &digest_len, EVP_sha256(), NULL)) {
        strcpy(out, "EVP_Digest-failed");
        return;
    }
    for(unsigned int i = 0; i < digest_len; ++i) {
        sprintf(out + 2U * i, "%02x", digest[i]);
    }
    out[2U * digest_len] = '\0';
}

static int resolve_offset(size_t kind, size_t ct_len, size_t ss_len, size_t *out)
{
    size_t boundary = ct_len - ss_len;

    switch(kind) {
        case 0: *out = 0; return 0;
        case 1: *out = 0; return 0;
        case 2: *out = boundary / 2U; return 0;
        case 3: *out = boundary - 1U; return 0;
        case 4: *out = boundary; return 0;
        case 5: *out = boundary + ss_len / 2U; return 0;
        case 6: *out = ct_len - 1U; return 0;
        case 7: *out = boundary / 2U; return 0;
        case 8: return -1;
        case 9: return -1;
        case 10: return -1;
        default: return -1;
    }
}

int main(int argc, char **argv)
{
    const char *sk_path;
    const char *ct_path;
    const char *ss_path;
    const char *outdir;
    unsigned char *sk, *ct_orig, *ss_orig, *ct, *ss;
    size_t sk_len_actual, ct_len_actual, ss_len_actual;
    size_t sk_len = kem_get_sk_len_bytes();
    size_t ct_len = kem_get_ct_len_bytes();
    size_t ss_len = kem_get_ss_len_bytes();
    char hash[65];
    int short_mode = (argc > 5 && strcmp(argv[5], "short") == 0);
    FILE *summary;
    char summary_path[1024];

    if(argc < 5 || sk_len == 0 || ct_len == 0 || ss_len == 0) {
        fprintf(stderr,
                "usage: %s SK CT SS OUTDIR [short|full]\n", argv[0]);
        return 2;
    }
    sk_path = argv[1];
    ct_path = argv[2];
    ss_path = argv[3];
    outdir = argv[4];

    if(ensure_dir(outdir) != 0) {
        return 2;
    }
    sk = read_blob(sk_path, sk_len, &sk_len_actual);
    ct_orig = read_blob(ct_path, ct_len, &ct_len_actual);
    ss_orig = read_blob(ss_path, ss_len, &ss_len_actual);
    ct = malloc(ct_len);
    ss = malloc(ss_len);
    if(sk == NULL || ct_orig == NULL || ss_orig == NULL || ct == NULL || ss == NULL) {
        return 2;
    }

    if(snprintf(summary_path, sizeof(summary_path), "%s/mutations.tsv", outdir) >=
       (int)sizeof(summary_path)) {
        return 2;
    }
    summary = fopen(summary_path, "w");
    if(summary == NULL) {
        return 2;
    }
    fprintf(summary,
            "label\tsecurity_bits\tprobe\toperation\toffset\txor_mask\t"
            "decaps_rc\tss_len\tss_sha256\tequals_expected\n");

    for(size_t i = 0; i < sizeof(MUTATIONS) / sizeof(MUTATIONS[0]); ++i) {
        const mutation_t *m = &MUTATIONS[i];
        size_t off = 0;
        unsigned long long returned_len = ss_len;
        int rc;
        int equal_expected;

        if(short_mode && i != 0 && i != 1 && i != 4) {
            continue;
        }
        memcpy(ct, ct_orig, ct_len);
        memset(ss, 0, ss_len);

        if(m->operation == MUT_SECOND_XOR) {
            ct[0] ^= 0x01U;
            ct[ct_len - ss_len] ^= 0x01U;
        } else if(m->operation == MUT_ZERO_BYTE) {
            if(m->offset_kind == 8) {
                memset(ct, 0, ct_len - ss_len);
            } else if(m->offset_kind == 9) {
                memset(ct + ct_len - ss_len, 0, ss_len);
            } else if(m->offset_kind == 10) {
                memset(ct, 0, ct_len);
            } else if(resolve_offset(m->offset_kind, ct_len, ss_len, &off) != 0) {
                continue;
            } else {
                ct[off] = 0x00U;
            }
        } else if(m->operation == MUT_FF_BYTE) {
            if(m->offset_kind == 9) {
                memset(ct + ct_len - ss_len, 0xff, ss_len);
            } else if(resolve_offset(m->offset_kind, ct_len, ss_len, &off) != 0) {
                continue;
            } else {
                ct[off] = 0xffU;
            }
        } else if(resolve_offset(m->offset_kind, ct_len, ss_len, &off) == 0) {
            ct[off] ^= m->xor_mask;
        } else {
            continue;
        }

        rc = kem_dec(sk, sk_len, ct, ct_len, ss, &returned_len);
        equal_expected = (rc == 0 && returned_len == ss_len &&
                          memcmp(ss, ss_orig, ss_len) == 0) ? 1 : 0;
        sha256_hex(ss, ss_len, hash);
        fprintf(summary,
                "%s\t%d\t%s\t%d\t%zu\t%02x\t%d\t%llu\t%s\t%d\n",
                HARNESS_LABEL, HARNESS_SECURITY_BITS, m->name,
                m->operation, off, m->xor_mask, rc, returned_len, hash,
                equal_expected);
        fflush(summary);
    }

    fclose(summary);
    free(sk);
    free(ct_orig);
    free(ss_orig);
    free(ct);
    free(ss);
    return 0;
}
