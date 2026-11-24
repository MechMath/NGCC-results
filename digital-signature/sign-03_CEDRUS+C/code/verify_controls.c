#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "api.h"

static unsigned char *read_file(const char *path, size_t *n) {
    FILE *f = fopen(path, "rb");
    unsigned char *p;
    long end;

    if (f == NULL) {
        perror(path);
        exit(2);
    }
    if (fseek(f, 0, SEEK_END) != 0 || (end = ftell(f)) < 0 ||
        fseek(f, 0, SEEK_SET) != 0) {
        perror(path);
        exit(2);
    }
    *n = (size_t)end;
    p = malloc(*n == 0 ? 1 : *n);
    if (p == NULL || (*n != 0 && fread(p, 1, *n, f) != *n)) {
        perror(path);
        exit(2);
    }
    if (fclose(f) != 0) {
        perror(path);
        exit(2);
    }
    return p;
}

int main(int argc, char **argv) {
    size_t pkn, mn, sn;
    unsigned char *pk;
    unsigned char *m;
    unsigned char *s;
    unsigned char *s_bad;
    unsigned char *m_bad;
    unsigned char *pk_bad;
    int forged;
    int sig_bad;
    int msg_bad;
    int pk_mut_bad;

    if (argc != 4) {
        fprintf(stderr, "usage: %s PUBLIC_KEY MESSAGE SIGNATURE\n", argv[0]);
        return 2;
    }

    pk = read_file(argv[1], &pkn);
    m = read_file(argv[2], &mn);
    s = read_file(argv[3], &sn);
    if (pkn != CRYPTO_PUBLICKEYBYTES || sn != CRYPTO_BYTES || mn == 0) {
        fprintf(stderr,
                "unexpected sizes: pk=%zu expected_pk=%d msg=%zu sig=%zu expected_sig=%d\n",
                pkn, CRYPTO_PUBLICKEYBYTES, mn, sn, CRYPTO_BYTES);
        return 3;
    }

    forged = crypto_sign_verify(s, sn, m, mn, pk);

    s_bad = malloc(sn);
    if (s_bad == NULL) return 2;
    memcpy(s_bad, s, sn);
    /* Offset SPX_N + COUNTER_SIZE + 17 lies in the first FORS block. */
    s_bad[SPX_N + 4 + 17] ^= 1;
    sig_bad = crypto_sign_verify(s_bad, sn, m, mn, pk);

    m_bad = malloc(mn);
    if (m_bad == NULL) return 2;
    memcpy(m_bad, m, mn);
    m_bad[0] ^= 1;
    msg_bad = crypto_sign_verify(s, sn, m_bad, mn, pk);

    pk_bad = malloc(pkn);
    if (pk_bad == NULL) return 2;
    memcpy(pk_bad, pk, pkn);
    pk_bad[0] ^= 1;
    pk_mut_bad = crypto_sign_verify(s, sn, m, mn, pk_bad);

    printf("implementation=Reference_Implementation/CEDRUSC-256f\n");
    printf("public_key_bytes=%zu\n", pkn);
    printf("message_bytes=%zu\n", mn);
    printf("signature_bytes=%zu\n", sn);
    printf("forged_verify_rc=%d\n", forged);
    printf("signature_one_bit_mutation_rc=%d\n", sig_bad);
    printf("message_one_bit_mutation_rc=%d\n", msg_bad);
    printf("public_key_one_bit_mutation_rc=%d\n", pk_mut_bad);

    free(pk_bad);
    free(m_bad);
    free(s_bad);
    free(s);
    free(m);
    free(pk);
    return (forged == 0 && sig_bad == -1 && msg_bad == -1 &&
            pk_mut_bad == -1) ? 0 : 1;
}
