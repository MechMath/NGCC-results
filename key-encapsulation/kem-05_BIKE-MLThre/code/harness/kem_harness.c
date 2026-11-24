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

static int ensure_dir(const char *path)
{
    if(mkdir(path, 0755) == 0 || errno == EEXIST) {
        return 0;
    }
    fprintf(stderr, "mkdir(%s): %s\n", path, strerror(errno));
    return -1;
}

static int write_blob(const char *dir,
                      const char *name,
                      const unsigned char *buf,
                      unsigned long long len)
{
    char path[1024];
    FILE *f;

    if(snprintf(path, sizeof(path), "%s/%s", dir, name) >= (int)sizeof(path)) {
        return -1;
    }
    f = fopen(path, "wb");
    if(f == NULL) {
        fprintf(stderr, "fopen(%s): %s\n", path, strerror(errno));
        return -1;
    }
    if(fwrite(buf, 1, (size_t)len, f) != (size_t)len || fclose(f) != 0) {
        fprintf(stderr, "write(%s) failed\n", path);
        return -1;
    }
    return 0;
}

static void sha256_hex(const unsigned char *buf,
                       unsigned long long len,
                       char out[65])
{
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;

    if(!EVP_Digest(buf, (size_t)len, digest, &digest_len, EVP_sha256(), NULL)) {
        strcpy(out, "EVP_Digest-failed");
        return;
    }
    for(unsigned int i = 0; i < digest_len; ++i) {
        sprintf(out + 2U * i, "%02x", digest[i]);
    }
    out[2U * digest_len] = '\0';
}

int main(int argc, char **argv)
{
    const char *outdir = (argc > 1) ? argv[1] : "harness-output";
    unsigned char seed[64];
    unsigned char *pk = NULL;
    unsigned char *sk = NULL;
    unsigned char *ct = NULL;
    unsigned char *ct_bad = NULL;
    unsigned char *ss = NULL;
    unsigned char *ss_dec = NULL;
    unsigned char *ss_bad = NULL;
    unsigned long long pk_len = 0;
    unsigned long long sk_len = 0;
    unsigned long long ct_len = 0;
    unsigned long long ss_len = 0;
    unsigned long long dec_len = 0;
    unsigned long long bad_len = 0;
    char pk_hash[65], sk_hash[65], ct_hash[65], ss_hash[65], bad_hash[65];
    int rc_key = -1, rc_enc = -1, rc_dec = -1, rc_bad = -1;
    int positive_ok;
    int negative_effect;
    int ret = 1;
    size_t mutation_offset;

    if(ensure_dir(outdir) != 0) {
        return 2;
    }

    memset(seed, 0, sizeof(seed));
    for(size_t i = 0; i < sizeof(seed); i += 4) {
        memcpy(seed + i, "seed", 4);
    }
    if(init_random_number(&drng_algorithm, seed, sizeof(seed)) != 0) {
        fprintf(stderr, "DRNG initialization failed\n");
        return 2;
    }

    pk_len = kem_get_pk_len_bytes();
    sk_len = kem_get_sk_len_bytes();
    ct_len = kem_get_ct_len_bytes();
    ss_len = kem_get_ss_len_bytes();
    if(pk_len == 0 || sk_len == 0 || ct_len == 0 || ss_len == 0) {
        fprintf(stderr, "invalid API lengths\n");
        return 2;
    }

    pk = calloc((size_t)pk_len, 1);
    sk = calloc((size_t)sk_len, 1);
    ct = calloc((size_t)ct_len, 1);
    ct_bad = calloc((size_t)ct_len, 1);
    ss = calloc((size_t)ss_len, 1);
    ss_dec = calloc((size_t)ss_len, 1);
    ss_bad = calloc((size_t)ss_len, 1);
    if(pk == NULL || sk == NULL || ct == NULL || ct_bad == NULL ||
       ss == NULL || ss_dec == NULL || ss_bad == NULL) {
        fprintf(stderr, "allocation failed\n");
        goto cleanup;
    }

    rc_key = kem_keygen(pk, &pk_len, sk, &sk_len);
    if(rc_key != 0) {
        goto cleanup;
    }
    rc_enc = kem_enc(pk, pk_len, ss, &ss_len, ct, &ct_len);
    if(rc_enc != 0) {
        goto cleanup;
    }
    dec_len = ss_len;
    rc_dec = kem_dec(sk, sk_len, ct, ct_len, ss_dec, &dec_len);
    positive_ok = (rc_dec == 0 && dec_len == ss_len &&
                   memcmp(ss, ss_dec, (size_t)ss_len) == 0);

    memcpy(ct_bad, ct, (size_t)ct_len);
    mutation_offset = (size_t)(ct_len / 2U);
    ct_bad[mutation_offset] ^= 0x01U;
    bad_len = ss_len;
    rc_bad = kem_dec(sk, sk_len, ct_bad, ct_len, ss_bad, &bad_len);
    negative_effect = (rc_bad != 0 || bad_len != ss_len ||
                       memcmp(ss, ss_bad, (size_t)ss_len) != 0);

    sha256_hex(pk, pk_len, pk_hash);
    sha256_hex(sk, sk_len, sk_hash);
    sha256_hex(ct, ct_len, ct_hash);
    sha256_hex(ss, ss_len, ss_hash);
    sha256_hex(ss_bad, ss_len, bad_hash);

    if(write_blob(outdir, "pk.bin", pk, pk_len) != 0 ||
       write_blob(outdir, "sk.bin", sk, sk_len) != 0 ||
       write_blob(outdir, "ct.bin", ct, ct_len) != 0 ||
       write_blob(outdir, "ct_mut.bin", ct_bad, ct_len) != 0 ||
       write_blob(outdir, "ss.bin", ss, ss_len) != 0 ||
       write_blob(outdir, "ss_mut.bin", ss_bad, ss_len) != 0) {
        goto cleanup;
    }

    printf("label\t%s\n", HARNESS_LABEL);
    printf("security_bits\t%d\n", HARNESS_SECURITY_BITS);
    printf("pk_len\t%llu\n", pk_len);
    printf("sk_len\t%llu\n", sk_len);
    printf("ct_len\t%llu\n", ct_len);
    printf("ss_len\t%llu\n", ss_len);
    printf("mutation_offset\t%zu\n", mutation_offset);
    printf("mutation_xor\t01\n");
    printf("keygen_rc\t%d\n", rc_key);
    printf("encaps_rc\t%d\n", rc_enc);
    printf("decaps_positive_rc\t%d\n", rc_dec);
    printf("decaps_mutated_rc\t%d\n", rc_bad);
    printf("positive_control\t%s\n", positive_ok ? "PASS" : "FAIL");
    printf("negative_control\t%s\n", negative_effect ? "PASS" : "FAIL");
    printf("pk_sha256\t%s\n", pk_hash);
    printf("sk_sha256\t%s\n", sk_hash);
    printf("ct_sha256\t%s\n", ct_hash);
    printf("ss_sha256\t%s\n", ss_hash);
    printf("ss_mutated_sha256\t%s\n", bad_hash);

    ret = (positive_ok && negative_effect) ? 0 : 1;

cleanup:
    free(pk);
    free(sk);
    free(ct);
    free(ct_bad);
    free(ss);
    free(ss_dec);
    free(ss_bad);
    return ret;
}
