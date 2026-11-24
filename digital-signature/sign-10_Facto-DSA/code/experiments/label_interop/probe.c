#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "SIG_AlgorithmInstance.h"
#include "drng.h"

DRNG_ctx drng_algorithm;

static int read_file(const char *path, unsigned char **buf, size_t *len)
{
    FILE *f = fopen(path, "rb");
    long n;
    if (!f) {
        fprintf(stderr, "open %s: %s\n", path, strerror(errno));
        return -1;
    }
    if (fseek(f, 0, SEEK_END) != 0 || (n = ftell(f)) < 0 ||
        fseek(f, 0, SEEK_SET) != 0) {
        fprintf(stderr, "size %s failed\n", path);
        fclose(f);
        return -1;
    }
    *buf = malloc((size_t)n ? (size_t)n : 1u);
    if (!*buf) {
        fclose(f);
        return -1;
    }
    if (fread(*buf, 1, (size_t)n, f) != (size_t)n) {
        fprintf(stderr, "read %s failed\n", path);
        free(*buf);
        *buf = NULL;
        fclose(f);
        return -1;
    }
    fclose(f);
    *len = (size_t)n;
    return 0;
}

static int write_file(const char *path, const unsigned char *buf, size_t len)
{
    FILE *f = fopen(path, "wb");
    if (!f) {
        fprintf(stderr, "open %s: %s\n", path, strerror(errno));
        return -1;
    }
    if (fwrite(buf, 1, len, f) != len || fclose(f) != 0) {
        fprintf(stderr, "write %s failed\n", path);
        return -1;
    }
    return 0;
}

static int init_seed(const char *path)
{
    unsigned char *seed = NULL;
    size_t len = 0;
    int rc;
    if (read_file(path, &seed, &len) != 0) {
        return -1;
    }
    rc = init_random_number(&drng_algorithm, seed, (unsigned long long)len);
    free(seed);
    return rc;
}

static int keygen_mode(const char *seed_path, const char *pk_path,
                       const char *sk_path)
{
    unsigned long long pk_len = sig_get_pk_len_bytes();
    unsigned long long sk_len = sig_get_sk_len_bytes();
    unsigned char *pk = calloc((size_t)pk_len, 1);
    unsigned char *sk = calloc((size_t)sk_len, 1);
    int rc;

    if (!pk || !sk) {
        free(pk);
        free(sk);
        return -1;
    }
    if (init_seed(seed_path) != 0) {
        free(pk);
        free(sk);
        return -1;
    }
    rc = sig_keygen(pk, &pk_len, sk, &sk_len);
    if (rc == 0) {
        if (write_file(pk_path, pk, (size_t)pk_len) != 0 ||
            write_file(sk_path, sk, (size_t)sk_len) != 0) {
            rc = -100;
        }
    }
    printf("mode=keygen rc=%d pk_len=%llu sk_len=%llu\n",
           rc, pk_len, sk_len);
    free(pk);
    free(sk);
    return rc;
}

static int sign_mode(const char *seed_path, const char *pk_path,
                     const char *sk_path, const char *msg_path,
                     const char *sig_path)
{
    unsigned char *pk = NULL, *sk = NULL, *msg = NULL;
    unsigned char *sig = NULL;
    size_t pk_file_len = 0, sk_file_len = 0, msg_len = 0;
    unsigned long long sk_len;
    unsigned long long sig_len = sig_get_sn_len_bytes();
    int rc, self_rc = -999;

    if (read_file(pk_path, &pk, &pk_file_len) != 0 ||
        read_file(sk_path, &sk, &sk_file_len) != 0 ||
        read_file(msg_path, &msg, &msg_len) != 0) {
        goto out;
    }
    sig = calloc((size_t)sig_len, 1);
    if (!sig) {
        goto out;
    }
    sk_len = (unsigned long long)sk_file_len;
    if (init_seed(seed_path) != 0) {
        goto out;
    }
    rc = sig_sign(sk, sk_len, msg, (unsigned long long)msg_len, sig, &sig_len);
    if (rc == 0) {
        self_rc = sig_verify(pk, (unsigned long long)pk_file_len, sig, sig_len,
                             msg, (unsigned long long)msg_len);
        if (write_file(sig_path, sig, (size_t)sig_len) != 0) {
            rc = -100;
        }
    }
    printf("mode=sign rc=%d self_rc=%d pk_len=%zu sk_len=%zu msg_len=%zu sig_len=%llu\n",
           rc, self_rc, pk_file_len, sk_file_len, msg_len, sig_len);
    free(pk);
    free(sk);
    free(msg);
    free(sig);
    return rc;

out:
    printf("mode=sign rc=-1 self_rc=%d pk_len=%zu sk_len=%zu msg_len=%zu sig_len=0\n",
           self_rc, pk_file_len, sk_file_len, msg_len);
    free(pk);
    free(sk);
    free(msg);
    free(sig);
    return -1;
}

static int verify_mode(const char *pk_path, const char *msg_path,
                       const char *sig_path)
{
    unsigned char *pk = NULL, *msg = NULL, *sig = NULL;
    size_t pk_len = 0, msg_len = 0, sig_len = 0;
    int rc;
    if (read_file(pk_path, &pk, &pk_len) != 0 ||
        read_file(msg_path, &msg, &msg_len) != 0 ||
        read_file(sig_path, &sig, &sig_len) != 0) {
        rc = -100;
    } else {
        rc = sig_verify(pk, (unsigned long long)pk_len, sig,
                        (unsigned long long)sig_len, msg,
                        (unsigned long long)msg_len);
    }
    printf("mode=verify rc=%d pk_len=%zu msg_len=%zu sig_len=%zu\n",
           rc, pk_len, msg_len, sig_len);
    free(pk);
    free(msg);
    free(sig);
    return rc;
}

int main(int argc, char **argv)
{
    if (argc == 5 && strcmp(argv[1], "keygen") == 0) {
        return keygen_mode(argv[2], argv[3], argv[4]);
    }
    if (argc == 7 && strcmp(argv[1], "sign") == 0) {
        return sign_mode(argv[2], argv[3], argv[4], argv[5], argv[6]);
    }
    if (argc == 5 && strcmp(argv[1], "verify") == 0) {
        return verify_mode(argv[2], argv[3], argv[4]);
    }
    fprintf(stderr,
            "usage:\n"
            "  %s keygen SEED PK SK\n"
            "  %s sign SEED PK SK MSG SIG\n"
            "  %s verify PK MSG SIG\n",
            argv[0], argv[0], argv[0]);
    return 64;
}
