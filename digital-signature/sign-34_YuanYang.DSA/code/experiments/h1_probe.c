#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "SIG_AlgorithmInstance.h"
#include "auxfunc.h"
#include "yuanyang_inner.h"
#include "yuanyang_params.h"

static int hexval(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int parse_hex(const char *line, const char *label,
                     unsigned char *out, size_t out_len)
{
    const char *p = strchr(line, '=');
    size_t i;
    if (p == NULL || strncmp(line, label, strlen(label)) != 0) return 0;
    p++;
    while (isspace((unsigned char)*p)) p++;
    for (i = 0; i < out_len; i++) {
        int hi = hexval((unsigned char)p[2 * i]);
        int lo = hexval((unsigned char)p[2 * i + 1]);
        if (hi < 0 || lo < 0) return 0;
        out[i] = (unsigned char)((hi << 4) | lo);
    }
    return !isxdigit((unsigned char)p[2 * out_len]);
}

static int parse_len(const char *line, const char *label, size_t *out)
{
    const char *p = strchr(line, '=');
    char *end;
    unsigned long long value;
    if (p == NULL || strncmp(line, label, strlen(label)) != 0) return 0;
    value = strtoull(p + 1, &end, 10);
    if (end == p + 1) return 0;
    *out = (size_t)value;
    return 1;
}

static int load_vector0(const char *path, unsigned char **pk, size_t *pk_len,
                        unsigned char **m, size_t *m_len,
                        unsigned char **sn, size_t *sn_len)
{
    FILE *f = fopen(path, "rb");
    char *line = NULL;
    size_t cap = 0;
    ssize_t got;
    int active = 0;

    if (f == NULL) return 0;
    while ((got = getline(&line, &cap, f)) >= 0) {
        while (got > 0 && (line[got - 1] == '\n' || line[got - 1] == '\r'))
            line[--got] = '\0';
        if (strcmp(line, "Count = 0") == 0) {
            active = 1;
        } else if (active && strcmp(line, "Count = 1") == 0) {
            break;
        }
        if (!active) continue;
        if (parse_len(line, "PK_Len", pk_len)) {
            *pk = malloc(*pk_len);
        } else if (*pk && parse_hex(line, "PK", *pk, *pk_len)) {
            /* parsed */
        } else if (parse_len(line, "M_Len", m_len)) {
            *m = malloc(*m_len);
        } else if (*m && parse_hex(line, "M", *m, *m_len)) {
            /* parsed */
        } else if (parse_len(line, "Sn_Len", sn_len)) {
            *sn = malloc(*sn_len);
        } else if (*sn && parse_hex(line, "Sn", *sn, *sn_len)) {
            /* parsed */
        }
    }
    free(line);
    fclose(f);
    return *pk && *m && *sn &&
           *pk_len == YUANYANG_PK_BYTES &&
           *m_len > 0 &&
           *sn_len == YUANYANG_SIGNATURE_BYTES;
}

static void challenge_from_seed(uint16_t c[YUANYANG_D],
                                const unsigned char *salt,
                                const unsigned char seed[32])
{
    if (yuanyang_hash_to_challenge(c, salt, seed) != YUANYANG_SUCCESS) {
        fprintf(stderr, "hash_to_challenge failed\n");
        exit(2);
    }
}

static void challenge_from_bytes(uint16_t c[YUANYANG_D],
                                 const unsigned char *input,
                                 size_t input_len)
{
    enum {
        ACCEPT_BOUND = (65536u / YUANYANG_Q) * YUANYANG_Q,
        MIN_SAMPLES = (YUANYANG_D * 65536u + ACCEPT_BOUND - 1u) / ACCEPT_BOUND,
        MARGIN_SAMPLES = YUANYANG_D >> 4,
        STREAM_BYTES = 2u * (MIN_SAMPLES + MARGIN_SAMPLES)
    };
    unsigned char stream[STREAM_BYTES];
    size_t off = 0, idx = 0;

    if (pseudoXOF(8u * STREAM_BYTES, input, 8u * input_len, stream) != 0) {
        fprintf(stderr, "pseudoXOF failed\n");
        exit(2);
    }
    while (idx < YUANYANG_D) {
        unsigned value;
        if (off + 2u > sizeof stream) {
            fprintf(stderr, "fixed probe stream too short\n");
            exit(2);
        }
        value = ((unsigned)stream[off] << 8) | stream[off + 1u];
        off += 2u;
        if (value < ACCEPT_BOUND) c[idx++] = (uint16_t)(value % YUANYANG_Q);
    }
}

static uint64_t relation_norm(const unsigned char *sn,
                              const uint16_t h[YUANYANG_D],
                              const uint16_t c[YUANYANG_D])
{
    int16_t s1[YUANYANG_D];
    uint16_t hs1[YUANYANG_D];
    uint64_t norm = 0;
    size_t i;

    if (yuanyang_decode_signature_s1(s1, sn, YUANYANG_SIGNATURE_BYTES) !=
        YUANYANG_SUCCESS) {
        return UINT64_MAX;
    }
    yuanyang_mul_mod_xn_plus_1(hs1, h, s1);
    for (i = 0; i < YUANYANG_D; i++) {
        uint16_t s2_mod = (uint16_t)(((unsigned)c[i] + hs1[i]) % YUANYANG_Q);
        int32_t s2 = yuanyang_center_lift_q(s2_mod);
        norm += (uint64_t)((int64_t)s1[i] * s1[i]);
        norm += (uint64_t)((int64_t)s2 * s2);
    }
    return norm;
}

static size_t challenge_diff(const uint16_t a[YUANYANG_D],
                             const uint16_t b[YUANYANG_D])
{
    size_t i, diff = 0;
    for (i = 0; i < YUANYANG_D; i++) diff += a[i] != b[i];
    return diff;
}

static void print_hex32(const char *label, const unsigned char x[32])
{
    size_t i;
    printf("%s=", label);
    for (i = 0; i < 32; i++) printf("%02X", x[i]);
    putchar('\n');
}

int main(int argc, char **argv)
{
    unsigned char *pk = NULL, *m = NULL, *sn = NULL;
    size_t pk_len = 0, m_len = 0, sn_len = 0;
    uint16_t h[YUANYANG_D], c_h[YUANYANG_D], c_pk[YUANYANG_D];
    uint16_t c_wire[YUANYANG_D];
    unsigned char *m_pk, *m_pk_salt;
    unsigned char seed_h[32], seed_pk[32];
    uint64_t norm_h, norm_pk, norm_wire;
    int verify_rc;

    if (argc != 2) {
        fprintf(stderr, "usage: %s KAT_SIG_YuanYang-512.txt\n", argv[0]);
        return 2;
    }
    if (!load_vector0(argv[1], &pk, &pk_len, &m, &m_len, &sn, &sn_len)) {
        fprintf(stderr, "failed to parse vector 0\n");
        return 2;
    }
    if (yuanyang_decode_public_key(h, pk, pk_len) != YUANYANG_SUCCESS) {
        fprintf(stderr, "public-key decode failed\n");
        return 2;
    }

    m_pk = malloc(m_len + pk_len);
    m_pk_salt = malloc(m_len + pk_len + YUANYANG_SALT_BYTES);
    if (m_pk == NULL || m_pk_salt == NULL) return 2;
    memcpy(m_pk, m, m_len);
    memcpy(m_pk + m_len, pk, pk_len);
    memcpy(m_pk_salt, sn, YUANYANG_SALT_BYTES);
    memcpy(m_pk_salt + YUANYANG_SALT_BYTES, m_pk, m_len + pk_len);

    if (yuanyang_hash_message_with_public_key(seed_h, m, m_len, h) != 0) return 2;
    if (sm3hash(256, m_pk, 8u * (m_len + pk_len), seed_pk) != 0) return 2;
    challenge_from_seed(c_h, sn, seed_h);
    challenge_from_seed(c_pk, sn, seed_pk);
    challenge_from_bytes(c_wire, m_pk_salt, m_len + pk_len + YUANYANG_SALT_BYTES);
    norm_h = relation_norm(sn, h, c_h);
    norm_pk = relation_norm(sn, h, c_pk);
    norm_wire = relation_norm(sn, h, c_wire);
    verify_rc = sig_verify(pk, pk_len, sn, sn_len, m, m_len);

    printf("profile_d=%u\n", YUANYANG_D);
    printf("pk_len=%zu\nm_len=%zu\nsn_len=%zu\nsalt_len=%u\n",
           pk_len, m_len, sn_len, YUANYANG_SALT_BYTES);
    print_hex32("seed_h", seed_h);
    print_hex32("seed_pk", seed_pk);
    printf("seed_equal=%d\n", memcmp(seed_h, seed_pk, 32) == 0);
    printf("challenge_h_vs_pk_seed_diff=%zu\n", challenge_diff(c_h, c_pk));
    printf("challenge_h_vs_direct_salt_M_PK_diff=%zu\n",
           challenge_diff(c_h, c_wire));
    printf("submitted_verify_rc=%d\n", verify_rc);
    printf("norm_raw_h=%llu\n", (unsigned long long)norm_h);
    printf("norm_pk_seed=%llu\n", (unsigned long long)norm_pk);
    printf("norm_direct_salt_M_PK=%llu\n", (unsigned long long)norm_wire);
    printf("norm_bound_sq=%llu\n",
           (unsigned long long)YUANYANG_REJECTION_BOUND_SQ);
    printf("relation_accept_raw_h=%d\n", norm_h <= YUANYANG_REJECTION_BOUND_SQ);
    printf("relation_accept_pk_seed=%d\n", norm_pk <= YUANYANG_REJECTION_BOUND_SQ);
    printf("relation_accept_direct_salt_M_PK=%d\n",
           norm_wire <= YUANYANG_REJECTION_BOUND_SQ);
    printf("input_vector0_sha256_TBD\n");

    free(m_pk_salt);
    free(m_pk);
    free(sn);
    free(m);
    free(pk);
    return 0;
}
