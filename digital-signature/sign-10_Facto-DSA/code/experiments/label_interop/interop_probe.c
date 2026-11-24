#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "SIG_AlgorithmInstance.h"
#include "drng.h"

DRNG_ctx drng_algorithm;

static const unsigned char keygen_seed[64] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
};

static const unsigned char sign_seed[64] = {
    0x9f, 0x86, 0xd0, 0x81, 0x88, 0x4c, 0x7d, 0x65,
    0x9a, 0x2f, 0xea, 0xa0, 0xc5, 0x5a, 0xd0, 0x15,
    0xa3, 0xbf, 0x4f, 0x1b, 0x2b, 0x0b, 0x82, 0x2c,
    0xd1, 0x5d, 0x6c, 0x52, 0xb6, 0xfb, 0xa6, 0xa4,
    0x3f, 0x5c, 0x8c, 0xa1, 0x1e, 0x11, 0x7a, 0x89,
    0xb0, 0x2c, 0x2f, 0x07, 0x7f, 0xd7, 0x92, 0x2a,
    0x6b, 0xc5, 0x43, 0xe1, 0x13, 0x2c, 0xd6, 0xb4,
    0x48, 0x68, 0x99, 0xd7, 0xc0, 0x7b, 0x50, 0x9a,
};

static int write_file(const char *path, const unsigned char *buf, size_t len)
{
    FILE *f = fopen(path, "wb");
    if (!f) {
        fprintf(stderr, "open %s: %s\n", path, strerror(errno));
        return -1;
    }
    if (fwrite(buf, 1, len, f) != len) {
        fprintf(stderr, "write %s failed\n", path);
        fclose(f);
        return -1;
    }
    if (fclose(f) != 0) {
        fprintf(stderr, "close %s failed\n", path);
        return -1;
    }
    return 0;
}

static int read_file(const char *path, unsigned char *buf, size_t len)
{
    FILE *f = fopen(path, "rb");
    int extra;
    if (!f) {
        fprintf(stderr, "open %s: %s\n", path, strerror(errno));
        return -1;
    }
    if (fread(buf, 1, len, f) != len) {
        fprintf(stderr, "short read %s\n", path);
        fclose(f);
        return -1;
    }
    extra = fgetc(f);
    if (extra != EOF) {
        fprintf(stderr, "oversize file %s\n", path);
        fclose(f);
        return -1;
    }
    if (ferror(f)) {
        fprintf(stderr, "read %s failed\n", path);
        fclose(f);
        return -1;
    }
    fclose(f);
    return 0;
}

static int make_path(char *out, size_t out_len, const char *dir, const char *name)
{
    int n = snprintf(out, out_len, "%s/%s", dir, name);
    if (n < 0 || (size_t)n >= out_len) {
        fprintf(stderr, "path too long\n");
        return -1;
    }
    return 0;
}

static void fill_message(unsigned char *msg, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        msg[i] = (unsigned char)(0x20u + ((i * 131u + 17u) & 0x5fu));
    }
}

static int do_init(const char *dir)
{
    char pk_path[1024], sk_path[1024], msg_path[1024], sig_path[1024];
    const size_t msg_len = 56;
    const unsigned long long pk_len = sig_get_pk_len_bytes();
    const unsigned long long sk_cap = sig_get_sk_len_bytes();
    const unsigned long long sn_cap = sig_get_sn_len_bytes();
    unsigned long long pk_out = pk_len;
    unsigned long long sk_out = sk_cap;
    unsigned long long sn_out = sn_cap;
    unsigned char *pk = calloc((size_t)pk_len, 1);
    unsigned char *sk = calloc((size_t)sk_cap, 1);
    unsigned char *sn = calloc((size_t)sn_cap, 1);
    unsigned char msg[56];
    int rc = 1;

    if (!pk || !sk || !sn) {
        fprintf(stderr, "allocation failed\n");
        goto out;
    }
    fill_message(msg, msg_len);

    if (init_random_number(&drng_algorithm, keygen_seed, sizeof(keygen_seed)) != 0) {
        fprintf(stderr, "keygen reseed failed\n");
        goto out;
    }
    if (sig_keygen(pk, &pk_out, sk, &sk_out) != 0) {
        fprintf(stderr, "keygen failed\n");
        goto out;
    }
    if (init_random_number(&drng_algorithm, sign_seed, sizeof(sign_seed)) != 0) {
        fprintf(stderr, "sign reseed failed\n");
        goto out;
    }
    if (sig_sign(sk, sk_out, msg, msg_len, sn, &sn_out) != 0) {
        fprintf(stderr, "sign failed\n");
        goto out;
    }

    printf("keygen pk_len=%llu sk_len=%llu sign sn_len=%llu self_verify=%d\n",
           pk_out, sk_out, sn_out,
           sig_verify(pk, pk_out, sn, sn_out, msg, msg_len));

    if (make_path(pk_path, sizeof(pk_path), dir, "pk.bin") != 0 ||
        make_path(sk_path, sizeof(sk_path), dir, "sk.bin") != 0 ||
        make_path(msg_path, sizeof(msg_path), dir, "msg.bin") != 0 ||
        make_path(sig_path, sizeof(sig_path), dir, "sig_submitted.bin") != 0) {
        goto out;
    }
    if (write_file(pk_path, pk, (size_t)pk_out) != 0 ||
        write_file(sk_path, sk, (size_t)sk_out) != 0 ||
        write_file(msg_path, msg, msg_len) != 0 ||
        write_file(sig_path, sn, (size_t)sn_out) != 0) {
        goto out;
    }
    rc = 0;
out:
    free(sn);
    free(sk);
    free(pk);
    return rc;
}

static int do_resign(const char *dir, const char *sig_name)
{
    char sk_path[1024], msg_path[1024], sig_path[1024];
    const size_t msg_len = 56;
    const unsigned long long sk_len = sig_get_sk_len_bytes();
    const unsigned long long sn_cap = sig_get_sn_len_bytes();
    unsigned long long sn_out = sn_cap;
    unsigned char *sk = calloc((size_t)sk_len, 1);
    unsigned char *sn = calloc((size_t)sn_cap, 1);
    unsigned char msg[56];
    int rc = 1;

    if (!sk || !sn) {
        fprintf(stderr, "allocation failed\n");
        goto out;
    }
    if (make_path(sk_path, sizeof(sk_path), dir, "sk.bin") != 0 ||
        make_path(msg_path, sizeof(msg_path), dir, "msg.bin") != 0 ||
        make_path(sig_path, sizeof(sig_path), dir, sig_name) != 0) {
        goto out;
    }
    if (read_file(sk_path, sk, (size_t)sk_len) != 0 ||
        read_file(msg_path, msg, sizeof(msg)) != 0) {
        goto out;
    }
    if (init_random_number(&drng_algorithm, sign_seed, sizeof(sign_seed)) != 0) {
        fprintf(stderr, "sign reseed failed\n");
        goto out;
    }
    if (sig_sign(sk, sk_len, msg, msg_len, sn, &sn_out) != 0) {
        fprintf(stderr, "sign failed\n");
        goto out;
    }
    printf("resign file=%s sn_len=%llu sign_rc=0\n", sig_name, sn_out);
    if (write_file(sig_path, sn, (size_t)sn_out) != 0) {
        goto out;
    }
    rc = 0;
out:
    free(sn);
    free(sk);
    return rc;
}

static int do_verify(const char *dir, const char *sig_name)
{
    char pk_path[1024], msg_path[1024], sig_path[1024];
    const size_t msg_len = 56;
    const unsigned long long pk_len = sig_get_pk_len_bytes();
    const unsigned long long sn_len = sig_get_sn_len_bytes();
    unsigned char *pk = calloc((size_t)pk_len, 1);
    unsigned char *sn = calloc((size_t)sn_len, 1);
    unsigned char msg[56];
    int rc = 100;

    if (!pk || !sn) {
        fprintf(stderr, "allocation failed\n");
        return 101;
    }
    if (make_path(pk_path, sizeof(pk_path), dir, "pk.bin") != 0 ||
        make_path(msg_path, sizeof(msg_path), dir, "msg.bin") != 0 ||
        make_path(sig_path, sizeof(sig_path), dir, sig_name) != 0) {
        goto out;
    }
    if (read_file(pk_path, pk, (size_t)pk_len) != 0 ||
        read_file(msg_path, msg, sizeof(msg)) != 0 ||
        read_file(sig_path, sn, (size_t)sn_len) != 0) {
        goto out;
    }
    rc = sig_verify(pk, pk_len, sn, sn_len, msg, msg_len);
    printf("verify file=%s rc=%d accept=%d\n", sig_name, rc, rc == 0);
out:
    free(sn);
    free(pk);
    return rc == 0 ? 0 : 1;
}

int main(int argc, char **argv)
{
    if (argc == 3 && strcmp(argv[1], "init") == 0) {
        return do_init(argv[2]);
    }
    if (argc == 4 && strcmp(argv[1], "resign") == 0) {
        return do_resign(argv[2], argv[3]);
    }
    if (argc == 4 && strcmp(argv[1], "verify") == 0) {
        return do_verify(argv[2], argv[3]);
    }
    fprintf(stderr,
            "usage: %s init DIR | resign DIR SIG_NAME | verify DIR SIG_NAME\n",
            argv[0]);
    return 2;
}
