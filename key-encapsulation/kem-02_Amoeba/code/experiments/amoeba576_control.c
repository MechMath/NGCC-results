#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>

#include "KEM_AlgorithmInstance.h"
#include "auxfunc.h"
#include "cpapke.h"
#include "params.h"

#define OUTPUT_DIR "output"

static int write_file(const char *name, const uint8_t *data, size_t len) {
    char path[256];
    FILE *fp;

    if (snprintf(path, sizeof(path), "%s/%s", OUTPUT_DIR, name) >=
        (int)sizeof(path)) {
        return -1;
    }
    fp = fopen(path, "wb");
    if (fp == NULL) {
        fprintf(stderr, "fopen(%s): %s\n", path, strerror(errno));
        return -1;
    }
    if (fwrite(data, 1, len, fp) != len) {
        fprintf(stderr, "fwrite(%s): %s\n", path, strerror(errno));
        fclose(fp);
        return -1;
    }
    if (fclose(fp) != 0) {
        fprintf(stderr, "fclose(%s): %s\n", path, strerror(errno));
        return -1;
    }
    return 0;
}

static int first_diff(const uint8_t *a, const uint8_t *b, size_t len) {
    size_t i;
    for (i = 0; i < len; i++) {
        if (a[i] != b[i]) {
            return (int)i;
        }
    }
    return -1;
}

static int submitted_cmp_tag(const uint8_t *a, const uint8_t *b, int len) {
    int tag = 0;
    int i;
    for (i = 0; i < len; i += 4) {
        tag += (a[i] != b[i]);
    }
    return tag;
}

static int full_cmp_tag(const uint8_t *a, const uint8_t *b, int len) {
    int tag = 0;
    int i;
    for (i = 0; i < len; i++) {
        tag += (a[i] != b[i]);
    }
    return tag;
}

static void derive_kr_and_reencrypt(
    uint8_t kr[RLWE_SEED_LEN * 2],
    uint8_t ct2[RLWE_CPA_CT_LEN],
    const uint8_t sk[RLWE_CCA_SK_LEN],
    const uint8_t ct[RLWE_CCA_CT_LEN]) {
    uint8_t msg[RLWE_MSG_LEN];
    uint8_t hash_input[RLWE_MSG_LEN + 1 + RLWE_SEED_LEN] = {0};
    size_t out_len = 0;

    if (CPAPKE_Decrypt(msg, sk, ct) != 0) {
        fprintf(stderr, "reproduction CPAPKE_Decrypt failed\n");
        return;
    }
    memcpy(hash_input, msg, RLWE_MSG_LEN);
    memcpy(hash_input + RLWE_MSG_LEN + 1,
           sk + RLWE_CPA_SK_LEN + RLWE_SEED_LEN, RLWE_SEED_LEN);

    while (out_len < RLWE_SEED_LEN * 2) {
        sm3hash(256, hash_input, sizeof(hash_input) * 8, kr + out_len);
        hash_input[RLWE_MSG_LEN]++;
        out_len += 32;
    }
    CPAPKE_Encrypt(ct2, sk + RLWE_CPA_SK_LEN, hash_input, kr + RLWE_SEED_LEN);
}

static void derive_key(
    uint8_t key[RLWE_KEY_LEN],
    const uint8_t ct[RLWE_CCA_CT_LEN],
    const uint8_t trailing[RLWE_SEED_LEN]) {
    uint8_t state[RLWE_CCA_CT_LEN + RLWE_SEED_LEN];
    memcpy(state, ct, RLWE_CCA_CT_LEN);
    memcpy(state + RLWE_CCA_CT_LEN, trailing, RLWE_SEED_LEN);
    pseudoXOF(RLWE_KEY_LEN * 8, state, sizeof(state) * 8, key);
}

int main(void) {
    uint8_t seed[64];
    uint8_t pk[RLWE_CCA_PK_LEN];
    uint8_t sk[RLWE_CCA_SK_LEN];
    uint8_t ct[RLWE_CCA_CT_LEN];
    uint8_t ct_pad[RLWE_CCA_CT_LEN];
    uint8_t ct_checked[RLWE_CCA_CT_LEN];
    uint8_t sender_key[RLWE_KEY_LEN];
    uint8_t decoded_key[RLWE_KEY_LEN];
    uint8_t positive_key[RLWE_KEY_LEN];
    uint8_t pad_key[RLWE_KEY_LEN];
    uint8_t checked_key[RLWE_KEY_LEN];
    uint8_t expected_key[RLWE_KEY_LEN];
    uint8_t rejection_key[RLWE_KEY_LEN];
    uint8_t kr[RLWE_SEED_LEN * 2];
    uint8_t ct2[RLWE_CPA_CT_LEN];
    unsigned long long pk_len = RLWE_CCA_PK_LEN;
    unsigned long long sk_len = RLWE_CCA_SK_LEN;
    unsigned long long ss_len = RLWE_KEY_LEN;
    unsigned long long ct_len = RLWE_CCA_CT_LEN;
    unsigned long long out_ss_len;
    int i;
    int keygen_rc;
    int enc_rc;
    int pos_rc;
    int pad_rc;
    int checked_rc;
    int pos_equal;
    int pad_equal;
    int checked_equal;
    int pad_expected_equal;
    int pad_rejection_equal;
    int checked_expected_equal;
    int checked_rejection_equal;
    int pad_first_diff;
    int checked_first_diff;
    int pad_submitted_tag;
    int pad_full_tag;
    int checked_submitted_tag;
    int checked_full_tag;

    if (mkdir(OUTPUT_DIR, 0755) != 0 && errno != EEXIST) {
        fprintf(stderr, "mkdir(%s): %s\n", OUTPUT_DIR, strerror(errno));
        return 1;
    }

    for (i = 0; i < (int)sizeof(seed); i++) {
        seed[i] = (uint8_t)i;
    }
    if (init_random_number(&drng_algorithm, seed, sizeof(seed)) != 0) {
        fprintf(stderr, "init_random_number failed\n");
        return 1;
    }

    memset(pk, 0, sizeof(pk));
    memset(sk, 0, sizeof(sk));
    memset(ct, 0, sizeof(ct));
    memset(sender_key, 0, sizeof(sender_key));
    memset(decoded_key, 0, sizeof(decoded_key));

    keygen_rc = kem_keygen(pk, &pk_len, sk, &sk_len);
    enc_rc = kem_enc(pk, pk_len, sender_key, &ss_len, ct, &ct_len);
    out_ss_len = RLWE_KEY_LEN;
    pos_rc = kem_dec(sk, sk_len, ct, ct_len, decoded_key, &out_ss_len);
    pos_equal = memcmp(sender_key, decoded_key, RLWE_KEY_LEN) == 0;
    memcpy(positive_key, decoded_key, RLWE_KEY_LEN);

    memcpy(ct_pad, ct, sizeof(ct));
    ct_pad[RLWE_CCA_CT_LEN - 1] ^= 0x01;
    memset(decoded_key, 0, sizeof(decoded_key));
    out_ss_len = RLWE_KEY_LEN;
    pad_rc = kem_dec(sk, sk_len, ct_pad, ct_len, decoded_key, &out_ss_len);
    pad_equal = memcmp(sender_key, decoded_key, RLWE_KEY_LEN) == 0;
    memcpy(pad_key, decoded_key, RLWE_KEY_LEN);
    {
        uint8_t pad_decoded_key[RLWE_KEY_LEN];
        memcpy(pad_decoded_key, decoded_key, sizeof(pad_decoded_key));
        derive_kr_and_reencrypt(kr, ct2, sk, ct_pad);
        derive_key(expected_key, ct_pad, kr);
        derive_key(rejection_key, ct_pad,
                   sk + RLWE_CPA_SK_LEN + RLWE_CPA_PK_LEN);
        pad_expected_equal =
            memcmp(pad_decoded_key, expected_key, RLWE_KEY_LEN) == 0;
        pad_rejection_equal =
            memcmp(pad_decoded_key, rejection_key, RLWE_KEY_LEN) == 0;
        pad_first_diff = first_diff(ct_pad, ct2, RLWE_CPA_CT_LEN);
        pad_submitted_tag = submitted_cmp_tag(ct_pad, ct2, RLWE_CPA_CT_LEN);
        pad_full_tag = full_cmp_tag(ct_pad, ct2, RLWE_CPA_CT_LEN);
        memcpy(ct_checked, ct, sizeof(ct));
        ct_checked[RLWE_CCA_CT_LEN - 3] ^= 0x01;
        memset(decoded_key, 0, sizeof(decoded_key));
        out_ss_len = RLWE_KEY_LEN;
        checked_rc =
            kem_dec(sk, sk_len, ct_checked, ct_len, decoded_key, &out_ss_len);
        checked_equal = memcmp(sender_key, decoded_key, RLWE_KEY_LEN) == 0;
        memcpy(checked_key, decoded_key, RLWE_KEY_LEN);
        derive_key(expected_key, ct_checked, kr);
        derive_key(rejection_key, ct_checked,
                   sk + RLWE_CPA_SK_LEN + RLWE_CPA_PK_LEN);
        checked_expected_equal =
            memcmp(decoded_key, expected_key, RLWE_KEY_LEN) == 0;
        checked_rejection_equal =
            memcmp(decoded_key, rejection_key, RLWE_KEY_LEN) == 0;
        checked_first_diff =
            first_diff(ct_checked, ct2, RLWE_CPA_CT_LEN);
        checked_submitted_tag =
            submitted_cmp_tag(ct_checked, ct2, RLWE_CPA_CT_LEN);
        checked_full_tag = full_cmp_tag(ct_checked, ct2, RLWE_CPA_CT_LEN);
    }

    if (write_file("rng_seed.bin", seed, sizeof(seed)) ||
        write_file("pk.bin", pk, pk_len) ||
        write_file("sk.bin", sk, sk_len) ||
        write_file("ct.bin", ct, ct_len) ||
        write_file("sender_key.bin", sender_key, ss_len) ||
        write_file("positive_key.bin", positive_key, ss_len) ||
        write_file("pad_flip_key.bin", pad_key, ss_len) ||
        write_file("checked_flip_key.bin", checked_key, ss_len) ||
        write_file("ct_pad_bit.bin", ct_pad, ct_len) ||
        write_file("ct_checked_byte.bin", ct_checked, ct_len) ||
        write_file("reencrypted_original.bin", ct2, RLWE_CPA_CT_LEN)) {
        return 1;
    }

    printf("profile=Amoeba-576\n");
    printf("security_level=%d\n", SECURITY_LEVEL);
    printf("seed_bytes=%zu\n", sizeof(seed));
    printf("pk_len=%llu\n", pk_len);
    printf("sk_len=%llu\n", sk_len);
    printf("ss_len=%llu\n", ss_len);
    printf("ct_len=%llu\n", ct_len);
    printf("keygen_rc=%d\n", keygen_rc);
    printf("enc_rc=%d\n", enc_rc);
    printf("positive_dec_rc=%d\n", pos_rc);
    printf("positive_key_equal=%d\n", pos_equal);
    printf("pad_flip_index=%d\n", RLWE_CCA_CT_LEN - 1);
    printf("pad_flip_mask=0x01\n");
    printf("pad_flip_dec_rc=%d\n", pad_rc);
    printf("pad_flip_key_equal_sender=%d\n", pad_equal);
    printf("pad_flip_matches_success_xof=%d\n", pad_expected_equal);
    printf("pad_flip_matches_rejection_xof=%d\n", pad_rejection_equal);
    printf("pad_flip_reencrypt_first_diff=%d\n", pad_first_diff);
    printf("pad_flip_submitted_cmp_tag=%d\n", pad_submitted_tag);
    printf("pad_flip_full_cmp_tag=%d\n", pad_full_tag);
    printf("checked_flip_index=%d\n", RLWE_CCA_CT_LEN - 3);
    printf("checked_flip_mask=0x01\n");
    printf("checked_flip_dec_rc=%d\n", checked_rc);
    printf("checked_flip_key_equal_sender=%d\n", checked_equal);
    printf("checked_flip_matches_success_xof=%d\n",
           checked_expected_equal);
    printf("checked_flip_matches_rejection_xof=%d\n",
           checked_rejection_equal);
    printf("checked_flip_reencrypt_first_diff=%d\n", checked_first_diff);
    printf("checked_flip_submitted_cmp_tag=%d\n",
           checked_submitted_tag);
    printf("checked_flip_full_cmp_tag=%d\n", checked_full_tag);
    return 0;
}
