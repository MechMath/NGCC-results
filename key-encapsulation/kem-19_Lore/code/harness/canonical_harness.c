#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "../work/Lore/Reference implementation/ref/api.h"
#include "../work/Lore/Reference implementation/ref/poly.h"

static void fill_seq(uint8_t *x, size_t n, uint8_t start) {
    for (size_t i = 0; i < n; ++i) {
        x[i] = (uint8_t)(start + (uint8_t)i);
    }
}

static int test_codec(void) {
    poly p = {0};
    poly q = {0};
    unsigned char main1[LORE_N] = {0};
    unsigned char main2[LORE_N] = {0};
    unsigned char overflow1[(LORE_N + 7) / 8 + 2] = {0};
    unsigned char overflow2[(LORE_N + 7) / 8 + 2] = {0};

    for (int i = 0; i < LORE_N; ++i) {
        p.coeffs[i] = (int16_t)(i % 257);
    }

    size_t nbits = lore_poly_pack_q_split(main1, overflow1, &p);
    int pos = 0;
    lore_poly_unpack_q_split(&q, main1, overflow1, &pos);
    size_t nbits2 = lore_poly_pack_q_split(main2, overflow2, &q);
    size_t nbytes = (nbits + 7) / 8;

    int ok = (nbits == nbits2) && (pos == (int)nbits) &&
             memcmp(main1, main2, LORE_N) == 0 &&
             memcmp(overflow1, overflow2, nbytes) == 0;
    for (int i = 0; i < LORE_N; ++i) {
        uint16_t expected = (uint16_t)(i % 257);
        ok &= ((uint16_t)q.coeffs[i] == expected);
    }
    printf("codec-roundtrip %s overflow_bits=%zu\n", ok ? "PASS" : "FAIL", nbits);

    memset(&p, 0, sizeof(p));
    memset(&q, 0, sizeof(q));
    memset(main1, 0, sizeof(main1));
    memset(overflow1, 0, sizeof(overflow1));
    p.coeffs[0] = 256;
    nbits = lore_poly_pack_q_split(main1, overflow1, &p);
    overflow1[0] |= 0xFE; /* Set unrelated bits after the sole meaningful bit. */
    pos = 0;
    lore_poly_unpack_q_split(&q, main1, overflow1, &pos);
    int trailing_ok = (nbits == 1) && (pos == 1) &&
                      (q.coeffs[0] == 256);
    printf("codec-trailing-bits-ignored %s consumed=%d\n",
           trailing_ok ? "PASS" : "FAIL", pos);
    return (ok && trailing_ok) ? 0 : 1;
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    const char *mode = (argc > 1) ? argv[1] : "derand";
    uint8_t *pk = calloc(CRYPTO_PUBLICKEYBYTES, 1);
    uint8_t *sk = calloc(CRYPTO_SECRETKEYBYTES, 1);
    uint8_t *ct1 = calloc(CRYPTO_CIPHERTEXTBYTES, 1);
    uint8_t *ct2 = calloc(CRYPTO_CIPHERTEXTBYTES, 1);
    uint8_t *pk2 = calloc(CRYPTO_PUBLICKEYBYTES, 1);
    uint8_t *sk2 = calloc(CRYPTO_SECRETKEYBYTES, 1);
    uint8_t ss1[CRYPTO_BYTES] = {0};
    uint8_t ss2[CRYPTO_BYTES] = {0};
    uint8_t ss3[CRYPTO_BYTES] = {0};
    uint8_t kp_coins[CRYPTO_KEYPAIRCOINBYTES];
    uint8_t enc_coins[CRYPTO_ENCCOINBYTES];

    if (!pk || !sk || !ct1 || !ct2 || !pk2 || !sk2) {
        fprintf(stderr, "allocation failed\n");
        return 2;
    }
    fill_seq(kp_coins, sizeof(kp_coins), 0x00);
    fill_seq(enc_coins, sizeof(enc_coins), 0x80);

    printf("level=%d alg=%s pk=%d sk=%d ct=%d ss=%d kb_coins=%d enc_coins=%d "
           "msg_bytes=%d hash_buf_bytes=%d mode=%s\n",
           LORE_LEVEL, CRYPTO_ALGNAME, CRYPTO_PUBLICKEYBYTES,
           CRYPTO_SECRETKEYBYTES, CRYPTO_CIPHERTEXTBYTES, CRYPTO_BYTES,
           CRYPTO_KEYPAIRCOINBYTES, CRYPTO_ENCCOINBYTES, LORE_MSG_BYTES,
           LORE_MSG_BYTES + LORE_SYMBYTES, mode);

    if (crypto_kem_keypair_derand(pk, sk, kp_coins) != 0 ||
        crypto_kem_keypair_derand(pk2, sk2, kp_coins) != 0) {
        fprintf(stderr, "deterministic keypair returned failure\n");
        return 1;
    }
    printf("deterministic-keypair %s\n",
           (!memcmp(pk, pk2, CRYPTO_PUBLICKEYBYTES) &&
            !memcmp(sk, sk2, CRYPTO_SECRETKEYBYTES)) ? "PASS" : "FAIL");

    if (!strcmp(mode, "derand")) {
        if (crypto_kem_enc_derand(ct1, ss1, pk, enc_coins) != 0 ||
            crypto_kem_enc_derand(ct2, ss2, pk, enc_coins) != 0) {
            fprintf(stderr, "deterministic encapsulation returned failure\n");
            return 1;
        }
        printf("deterministic-encaps %s\n",
               (!memcmp(ct1, ct2, CRYPTO_CIPHERTEXTBYTES) &&
                !memcmp(ss1, ss2, CRYPTO_BYTES)) ? "PASS" : "FAIL");
    } else if (!strcmp(mode, "guardcoins")) {
        long pagesz = sysconf(_SC_PAGESIZE);
        uint8_t *mapping = mmap(NULL, (size_t)(2 * pagesz), PROT_READ | PROT_WRITE,
                                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (mapping == MAP_FAILED || pagesz < CRYPTO_ENCCOINBYTES ||
            mprotect(mapping + pagesz, (size_t)pagesz, PROT_NONE) != 0) {
            fprintf(stderr, "guard-page setup failed\n");
            return 2;
        }
        uint8_t *guarded_coins = mapping + pagesz - CRYPTO_ENCCOINBYTES;
        fill_seq(guarded_coins, CRYPTO_ENCCOINBYTES, 0x80);
        printf("guardcoins: %d readable bytes immediately before PROT_NONE page\n",
               CRYPTO_ENCCOINBYTES);
        if (crypto_kem_enc_derand(ct1, ss1, pk, guarded_coins) != 0) {
            fprintf(stderr, "guarded deterministic encapsulation returned failure\n");
            return 1;
        }
    } else if (!strcmp(mode, "random")) {
        if (crypto_kem_enc(ct1, ss1, pk) != 0) {
            fprintf(stderr, "randomized encapsulation returned failure\n");
            return 1;
        }
    } else {
        fprintf(stderr, "unknown mode\n");
        return 2;
    }

    if (crypto_kem_dec(ss3, ct1, sk) != 0) {
        fprintf(stderr, "decapsulation returned failure\n");
        return 1;
    }
    printf("roundtrip %s\n", !memcmp(ss1, ss3, CRYPTO_BYTES) ? "PASS" : "FAIL");

    ct2[0] ^= 1;
    memset(ss2, 0, sizeof(ss2));
    memset(ss3, 0, sizeof(ss3));
    crypto_kem_dec(ss2, ct2, sk);
    crypto_kem_dec(ss3, ct2, sk);
    printf("mutated-ct-deterministic-reject %s\n",
           !memcmp(ss2, ss3, CRYPTO_BYTES) ? "PASS" : "FAIL");
    printf("mutated-ct-accept-as-valid %s\n",
           !memcmp(ss2, ss1, CRYPTO_BYTES) ? "YES" : "NO");

    int codec = test_codec();
    free(pk);
    free(sk);
    free(ct1);
    free(ct2);
    free(pk2);
    free(sk2);
    return codec;
}
