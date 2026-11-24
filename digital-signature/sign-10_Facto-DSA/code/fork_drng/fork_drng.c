#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "SIG_AlgorithmInstance.h"
#include "drng.h"

extern DRNG_ctx drng_algorithm;

static int write_bytes(const char *dir, const char *name,
                       const unsigned char *p, size_t n)
{
    char path[1024];
    FILE *f;
    if (snprintf(path, sizeof(path), "%s/%s", dir, name) >= (int)sizeof(path))
        return -1;
    f = fopen(path, "wb");
    if (f == NULL)
        return -1;
    if (n != 0 && fwrite(p, 1, n, f) != n) {
        fclose(f);
        return -1;
    }
    return fclose(f) == 0 ? 0 : -1;
}

static int write_rc(const char *dir, const char *name,
                    int rc, unsigned long long pk_len,
                    unsigned long long sk_len, unsigned long long sn_len)
{
    char path[1024];
    FILE *f;
    int ok;
    if (snprintf(path, sizeof(path), "%s/%s", dir, name) >= (int)sizeof(path))
        return -1;
    f = fopen(path, "w");
    if (f == NULL)
        return -1;
    ok = fprintf(f, "rc=%d\npk_len=%llu\nsk_len=%llu\nsn_len=%llu\n",
                 rc, pk_len, sk_len, sn_len) > 0;
    if (fclose(f) != 0)
        ok = 0;
    return ok ? 0 : -1;
}

static void deterministic_seed(unsigned char seed[64], unsigned char tag)
{
    size_t i;
    for (i = 0; i < 64; i++)
        seed[i] = (unsigned char)(tag ^ (unsigned char)(i * 37u));
}

static int do_keygen(const char *dir, const char *prefix)
{
    unsigned long long pk_len = sig_get_pk_len_bytes();
    unsigned long long sk_len = sig_get_sk_len_bytes();
    unsigned char *pk = calloc((size_t)pk_len, 1);
    unsigned char *sk = calloc((size_t)sk_len, 1);
    unsigned long long pk_out = pk_len;
    unsigned long long sk_out = sk_len;
    int rc;
    char pk_name[128], sk_name[128], rc_name[128];

    if (pk == NULL || sk == NULL)
        return 2;
    if (snprintf(pk_name, sizeof(pk_name), "%s.pk", prefix) >= (int)sizeof(pk_name) ||
        snprintf(sk_name, sizeof(sk_name), "%s.sk", prefix) >= (int)sizeof(sk_name) ||
        snprintf(rc_name, sizeof(rc_name), "%s.rc", prefix) >= (int)sizeof(rc_name)) {
        free(sk);
        free(pk);
        return 3;
    }
    rc = sig_keygen(pk, &pk_out, sk, &sk_out);
    if (write_rc(dir, rc_name, rc, pk_out, sk_out, 0) != 0 ||
        write_bytes(dir, pk_name, pk, (size_t)pk_out) != 0 ||
        write_bytes(dir, sk_name, sk, (size_t)sk_out) != 0) {
        free(sk);
        free(pk);
        return 3;
    }
    free(sk);
    free(pk);
    return rc == 0 ? 0 : 4;
}

static int produce_initial_key(const char *dir,
                               unsigned char **pk_out_buf,
                               unsigned char **sk_out_buf,
                               unsigned long long *pk_len_out,
                               unsigned long long *sk_len_out)
{
    unsigned long long pk_len = sig_get_pk_len_bytes();
    unsigned long long sk_len = sig_get_sk_len_bytes();
    unsigned char *pk = calloc((size_t)pk_len, 1);
    unsigned char *sk = calloc((size_t)sk_len, 1);
    unsigned long long got_pk = pk_len;
    unsigned long long got_sk = sk_len;
    int rc;

    if (pk == NULL || sk == NULL)
        return 2;
    rc = sig_keygen(pk, &got_pk, sk, &got_sk);
    if (rc != 0 ||
        write_bytes(dir, "initial.pk", pk, (size_t)got_pk) != 0 ||
        write_bytes(dir, "initial.sk", sk, (size_t)got_sk) != 0) {
        free(sk);
        free(pk);
        return 3;
    }
    *pk_out_buf = pk;
    *sk_out_buf = sk;
    *pk_len_out = got_pk;
    *sk_len_out = got_sk;
    return 0;
}

static int do_sign(const char *dir, const char *prefix,
                   unsigned char *pk, unsigned long long pk_len,
                   unsigned char *sk, unsigned long long sk_len)
{
    static const unsigned char msg[56] = {
        0x46,0x61,0x63,0x74,0x6f,0x2d,0x44,0x53,
        0x41,0x20,0x66,0x6f,0x72,0x6b,0x20,0x44,
        0x52,0x4e,0x47,0x20,0x61,0x75,0x64,0x69,
        0x74,0x20,0x77,0x69,0x74,0x6e,0x65,0x73,
        0x73,0x20,0x6d,0x65,0x73,0x73,0x61,0x67,
        0x65,0x20,0x30,0x30,0x30,0x30,0x30,0x30,
        0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37
    };
    unsigned long long sn_max = sig_get_sn_len_bytes();
    unsigned long long sn_len = sn_max;
    unsigned char *sn = calloc((size_t)sn_max + 1, 1);
    int rc, vr = -999;
    char rc_name[128], signature_name[128];

    if (sn == NULL)
        return 2;
    if (snprintf(rc_name, sizeof(rc_name), "%s.rc", prefix) >= (int)sizeof(rc_name) ||
        snprintf(signature_name, sizeof(signature_name), "%s.signature.bin", prefix) >=
            (int)sizeof(signature_name)) {
        free(sn);
        return 3;
    }
    rc = sig_sign(sk, sk_len, (unsigned char *)msg, sizeof(msg), sn, &sn_len);
    if (rc == 0)
        vr = sig_verify(pk, pk_len, sn, sn_len, (unsigned char *)msg, sizeof(msg));
    if (write_rc(dir, rc_name, rc, vr, 0, sn_len) != 0 ||
        write_bytes(dir, signature_name, sn, (size_t)sn_len) != 0) {
        free(sn);
        return 3;
    }
    free(sn);
    return rc == 0 && vr == 0 ? 0 : 4;
}

static int fork_keygen(const char *dir)
{
    int initial_rc, child_status = 0, parent_rc;
    pid_t pid;
    if (do_keygen(dir, "pre.keygen") != 0)
        return 5;
    if (write_bytes(dir, "state.pre", (unsigned char *)&drng_algorithm,
                    sizeof(drng_algorithm)) != 0)
        return 6;
    pid = fork();
    if (pid < 0)
        return 7;
    if (pid == 0) {
        int rc = write_bytes(dir, "state.child.before",
                             (unsigned char *)&drng_algorithm,
                             sizeof(drng_algorithm));
        if (rc == 0)
            rc = do_keygen(dir, "child.keygen");
        _exit(rc);
    }
    if (write_bytes(dir, "state.parent.before", (unsigned char *)&drng_algorithm,
                    sizeof(drng_algorithm)) != 0)
        return 8;
    parent_rc = do_keygen(dir, "parent.keygen");
    if (waitpid(pid, &child_status, 0) != pid)
        return 9;
    initial_rc = WIFEXITED(child_status) ? WEXITSTATUS(child_status) : 128;
    printf("fork_keygen,parent_rc=%d,child_rc=%d,child_wait_status=%d\n",
           parent_rc, initial_rc, child_status);
    return 0;
}

static int fork_sign(const char *dir)
{
    unsigned char *pk = NULL, *sk = NULL;
    unsigned long long pk_len = 0, sk_len = 0;
    int parent_rc, child_status = 0, child_rc;
    pid_t pid;
    if (produce_initial_key(dir, &pk, &sk, &pk_len, &sk_len) != 0)
        return 5;
    /* Consume randomness in a valid sign call before the fork. */
    if (do_sign(dir, "pre.sign", pk, pk_len, sk, sk_len) != 0)
        return 6;
    if (write_bytes(dir, "state.pre", (unsigned char *)&drng_algorithm,
                    sizeof(drng_algorithm)) != 0)
        return 7;
    pid = fork();
    if (pid < 0)
        return 8;
    if (pid == 0) {
        int rc = write_bytes(dir, "state.child.before",
                             (unsigned char *)&drng_algorithm,
                             sizeof(drng_algorithm));
        if (rc == 0)
            rc = do_sign(dir, "child.sign", pk, pk_len, sk, sk_len);
        _exit(rc);
    }
    if (write_bytes(dir, "state.parent.before", (unsigned char *)&drng_algorithm,
                    sizeof(drng_algorithm)) != 0)
        return 9;
    parent_rc = do_sign(dir, "parent.sign", pk, pk_len, sk, sk_len);
    if (waitpid(pid, &child_status, 0) != pid)
        return 10;
    child_rc = WIFEXITED(child_status) ? WEXITSTATUS(child_status) : 128;
    printf("fork_sign,parent_rc=%d,child_rc=%d,child_wait_status=%d\n",
           parent_rc, child_rc, child_status);
    free(sk);
    free(pk);
    return 0;
}

static int fork_reseed(const char *dir)
{
    int child_status = 0, parent_rc;
    unsigned char seed_parent[64], seed_child[64];
    pid_t pid;
    if (do_keygen(dir, "pre.keygen") != 0)
        return 5;
    deterministic_seed(seed_parent, 0xA5);
    deterministic_seed(seed_child, 0x5A);
    if (write_bytes(dir, "state.pre", (unsigned char *)&drng_algorithm,
                    sizeof(drng_algorithm)) != 0)
        return 6;
    pid = fork();
    if (pid < 0)
        return 7;
    if (pid == 0) {
        int rc = init_random_number(&drng_algorithm, seed_child,
                                    sizeof(seed_child));
        if (rc == 0)
            rc = write_bytes(dir, "state.child.reseed",
                             (unsigned char *)&drng_algorithm,
                             sizeof(drng_algorithm));
        if (rc == 0)
            rc = do_keygen(dir, "child.keygen");
        _exit(rc);
    }
    if (init_random_number(&drng_algorithm, seed_parent,
                           sizeof(seed_parent)) != 0)
        return 8;
    if (write_bytes(dir, "state.parent.reseed",
                    (unsigned char *)&drng_algorithm,
                    sizeof(drng_algorithm)) != 0)
        return 9;
    parent_rc = do_keygen(dir, "parent.keygen");
    if (waitpid(pid, &child_status, 0) != pid)
        return 10;
    printf("fork_reseed,parent_rc=%d,child_rc=%d,child_wait_status=%d\n",
           parent_rc, WIFEXITED(child_status) ? WEXITSTATUS(child_status) : 128,
           child_status);
    return 0;
}

static int sequential(const char *dir)
{
    int rc;
    if (do_keygen(dir, "first.keygen") != 0)
        return 5;
    rc = do_keygen(dir, "second.keygen");
    if (rc != 0)
        return rc;
    return 0;
}

int main(int argc, char **argv)
{
    const char *mode, *dir;
    if (argc != 3) {
        fprintf(stderr, "usage: %s MODE OUTDIR\n", argv[0]);
        return 64;
    }
    mode = argv[1];
    dir = argv[2];
    if (strcmp(mode, "fork-keygen") == 0)
        return fork_keygen(dir);
    if (strcmp(mode, "fork-sign") == 0)
        return fork_sign(dir);
    if (strcmp(mode, "fork-reseed") == 0)
        return fork_reseed(dir);
    if (strcmp(mode, "sequential") == 0)
        return sequential(dir);
    if (strcmp(mode, "startup") == 0)
        return do_keygen(dir, "startup.keygen");
    fprintf(stderr, "unknown mode: %s\n", mode);
    return 64;
}
