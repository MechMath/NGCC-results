#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "SIG_AlgorithmInstance.h"
#include "drng.h"

DRNG_ctx drng_algorithm;

static void die(const char *what)
{
    fprintf(stderr, "fatal: %s\n", what);
    exit(2);
}

static void print_hex(const char *name, const uint8_t *p, size_t n)
{
    printf("\"%s\":\"", name);
    for (size_t i = 0; i < n; i++)
        printf("%02x", p[i]);
    printf("\"");
}

int main(int argc, char **argv)
{
    if (argc != 3)
        die("usage: harness VARIANT PROFILE");

    const size_t pk_n = (size_t)sig_get_pk_len_bytes();
    const size_t sk_n = (size_t)sig_get_sk_len_bytes();
    const size_t sn_n = (size_t)sig_get_sn_len_bytes();
    const size_t prefix_n = (size_t)DOVE_N;
    const size_t salt_n = (size_t)DOVE_SALT_BYTES;
    if (prefix_n + salt_n != sn_n)
        die("signature layout mismatch");

    /*
     * Deliberately overallocate every API buffer. The original pkc_skc sign
     * path transiently reads bytes beyond its declared seed-only sk length;
     * padding here ensures the harness itself never supplies an invalid
     * allocation. Length arguments remain the implementation-reported sizes.
     */
    const size_t pad = 4096;
    uint8_t *pk = calloc(pk_n + pad, 1);
    uint8_t *sk = calloc(sk_n + pad, 1);
    uint8_t *sn = calloc(sn_n + pad, 1);
    uint8_t *prefix_buf = calloc(sn_n + pad, 1);
    uint8_t *m = calloc(128, 1);
    if (!pk || !sk || !sn || !prefix_buf || !m)
        die("calloc");

    static const uint8_t seed[32] = {
        0x44,0x4f,0x56,0x45,0x2d,0x65,0x6e,0x76,
        0x65,0x6c,0x6f,0x70,0x65,0x2d,0x74,0x65,
        0x73,0x74,0x2d,0x32,0x30,0x32,0x36,0x31,
        0x31,0x31,0x33,0x2d,0x66,0x69,0x78,0x31
    };
    for (size_t i = 0; i < 96; i++)
        m[i] = (uint8_t)(0x31 + (i % 47));
    if (init_random_number(&drng_algorithm, seed, sizeof(seed)) != 0)
        die("init_random_number");

    uint64_t pk_out = pk_n, sk_out = sk_n, sn_out = sn_n;
    if (sig_keygen(pk, &pk_out, sk, &sk_out) != 0)
        die("sig_keygen");
    if (pk_out != pk_n || sk_out != sk_n)
        die("key length mismatch");
    if (sig_sign(sk, sk_n, m, 96, sn, &sn_out) != 0)
        die("sig_sign");
    if (sn_out != sn_n)
        die("signature length mismatch");

    memcpy(prefix_buf, sn, prefix_n);
    memset(prefix_buf + prefix_n, 0xa5, pad);

    printf("{");
    printf("\"variant\":\"%s\",\"profile\":\"%s\",", argv[1], argv[2]);
    printf("\"pk_len\":%zu,\"sk_len\":%zu,\"sn_len\":%zu,", pk_n, sk_n, sn_n);
    printf("\"declared_prefix_len\":%zu,\"declared_salt_len\":%zu,", prefix_n, salt_n);
    print_hex("pk_sha_input_truncated", pk, (pk_n < 32 ? pk_n : 32));
    printf(",");
    print_hex("message", m, 96);
    printf(",");
    print_hex("signature", sn, sn_n);

    int genuine = sig_verify(pk, pk_n, sn, sn_n, m, 96);
    printf(",\"genuine_accept\":%s,\"genuine_ret\":%d", genuine == 0 ? "true" : "false", genuine);

    size_t salt_single_accepts = 0;
    uint8_t *mut = malloc(sn_n);
    if (!mut)
        die("malloc mut");
    for (size_t i = 0; i < salt_n; i++) {
        memcpy(mut, sn, sn_n);
        mut[prefix_n + i] ^= 0x01;
        if (sig_verify(pk, pk_n, mut, sn_n, m, 96) == 0)
            salt_single_accepts++;
    }
    free(mut);
    printf(",\"salt_single_byte_mutations\":%zu,\"salt_single_byte_accepts\":%zu",
           salt_n, salt_single_accepts);

    size_t all_salt_accepts = 0;
    uint8_t *salt_mut = malloc(sn_n);
    if (!salt_mut)
        die("malloc salt_mut");
    memcpy(salt_mut, sn, sn_n);
    for (size_t i = 0; i < salt_n; i++)
        salt_mut[prefix_n + i] ^= 0xff;
    if (sig_verify(pk, pk_n, salt_mut, sn_n, m, 96) == 0)
        all_salt_accepts++;
    free(salt_mut);
    printf(",\"all_salt_bytes_flipped_accepts\":%zu", all_salt_accepts);

    size_t short_length_accepts = 0;
    size_t short_length_calls = 0;
    for (size_t declared = 0; declared <= sn_n; declared++) {
        if (sig_verify(pk, pk_n, prefix_buf, declared, m, 96) == 0)
            short_length_accepts++;
        short_length_calls++;
    }
    int absent_ret_0 = sig_verify(pk, pk_n, prefix_buf, 0, m, 96);
    int absent_ret_n = sig_verify(pk, pk_n, prefix_buf, prefix_n, m, 96);
    int absent_ret_ns1 = sig_verify(pk, pk_n, prefix_buf, sn_n - 1, m, 96);
    int absent_ret_ns = sig_verify(pk, pk_n, prefix_buf, sn_n, m, 96);
    printf(",\"absent_salt_declared_length_calls\":%zu,\"absent_salt_declared_length_accepts\":%zu",
           short_length_calls, short_length_accepts);
    printf(",\"absent_salt_ret_len_0\":%d,\"absent_salt_ret_len_N\":%d", absent_ret_0, absent_ret_n);
    printf(",\"absent_salt_ret_len_N_plus_SALT_minus_1\":%d,\"absent_salt_ret_len_N_plus_SALT\":%d",
           absent_ret_ns1, absent_ret_ns);

    uint8_t *ctrl = malloc(sn_n + pad);
    if (!ctrl)
        die("malloc ctrl");
    memcpy(ctrl, sn, sn_n);
    ctrl[0] ^= 0x01;
    int state_ret = sig_verify(pk, pk_n, ctrl, sn_n, m, 96);
    free(ctrl);

    uint8_t *pk_ctrl = malloc(pk_n + pad);
    if (!pk_ctrl)
        die("malloc pk_ctrl");
    memcpy(pk_ctrl, pk, pk_n);
    pk_ctrl[0] ^= 0x01;
    int pk_ret = sig_verify(pk_ctrl, pk_n, sn, sn_n, m, 96);
    free(pk_ctrl);

    uint8_t *m_ctrl = malloc(128);
    if (!m_ctrl)
        die("malloc m_ctrl");
    memcpy(m_ctrl, m, 96);
    m_ctrl[0] ^= 0x01;
    int msg_ret = sig_verify(pk, pk_n, sn, sn_n, m_ctrl, 96);
    free(m_ctrl);
    printf(",\"state_byte_mutation_ret\":%d,\"pk_byte_mutation_ret\":%d,\"message_byte_mutation_ret\":%d",
           state_ret, pk_ret, msg_ret);

    int all_ok = genuine == 0 &&
                 salt_single_accepts == salt_n &&
                 all_salt_accepts == 1 &&
                 short_length_accepts == short_length_calls &&
                 absent_ret_0 == 0 && absent_ret_n == 0 &&
                 absent_ret_ns1 == 0 && absent_ret_ns == 0 &&
                 state_ret != 0 && pk_ret != 0 && msg_ret != 0;
    printf(",\"all_expected\":%s}\n", all_ok ? "true" : "false");

    free(m);
    free(prefix_buf);
    free(sn);
    free(sk);
    free(pk);
    return all_ok ? 0 : 1;
}
