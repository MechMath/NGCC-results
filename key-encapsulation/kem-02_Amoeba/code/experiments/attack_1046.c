#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "auxfunc.h"
#include "cpapke.h"
#include "params.h"

extern int32_t cmp(uint8_t *c1, uint8_t *c2, int32_t len);
extern void ID(uint8_t id[RLWE_SEED_LEN], const uint8_t pk[RLWE_CCA_PK_LEN]);
extern void CCAKEM_KeyGen(
    uint8_t sk[RLWE_CCA_SK_LEN],
    uint8_t pk[RLWE_CCA_PK_LEN]);
extern void CCAKEM_Encaps(
    uint8_t ct[RLWE_CCA_CT_LEN],
    uint8_t key[RLWE_KEY_LEN],
    const uint8_t pk[RLWE_CCA_PK_LEN]);
extern int CCAKEM_Decaps(
    uint8_t key[RLWE_KEY_LEN],
    const uint8_t sk[RLWE_CCA_SK_LEN],
    const uint8_t ct[RLWE_CCA_CT_LEN]);

static int different(const uint8_t *a, const uint8_t *b, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        if (a[i] != b[i]) {
            return 1;
        }
    }
    return 0;
}

static void derive_kr(
    uint8_t kr[2 * RLWE_SEED_LEN],
    uint8_t message_domain[RLWE_MSG_LEN + 1 + RLWE_SEED_LEN],
    const uint8_t message[RLWE_MSG_LEN],
    const uint8_t pk[RLWE_CCA_PK_LEN]) {
    memcpy(message_domain, message, RLWE_MSG_LEN);
    message_domain[RLWE_MSG_LEN] = 0;
    ID(message_domain + RLWE_MSG_LEN + 1, pk);

    size_t output_length = 0;
    while (output_length < 2 * RLWE_SEED_LEN) {
        sm3hash(
            256,
            message_domain,
            (RLWE_MSG_LEN + 1 + RLWE_SEED_LEN) << 3,
            kr + output_length);
        message_domain[RLWE_MSG_LEN]++;
        output_length += 32;
    }
}

static void derive_explicit_key(
    uint8_t key[RLWE_KEY_LEN],
    const uint8_t ciphertext[RLWE_CCA_CT_LEN],
    const uint8_t suffix[RLWE_SEED_LEN]) {
    uint8_t state[RLWE_CCA_CT_LEN + RLWE_SEED_LEN];
    memcpy(state, ciphertext, RLWE_CCA_CT_LEN);
    memcpy(state + RLWE_CCA_CT_LEN, suffix, RLWE_SEED_LEN);
    pseudoXOF(
        RLWE_KEY_LEN << 3,
        state,
        (RLWE_CCA_CT_LEN + RLWE_SEED_LEN) << 3,
        key);
}

int main(void) {
    CPAPKE_Init();

    for (int trial = 0; trial < 16; ++trial) {
        uint8_t sk[RLWE_CCA_SK_LEN] = {0};
        uint8_t pk[RLWE_CCA_PK_LEN] = {0};
        uint8_t ct[RLWE_CCA_CT_LEN] = {0};
        uint8_t ct_tampered[RLWE_CCA_CT_LEN] = {0};
        uint8_t original_key[RLWE_KEY_LEN] = {0};
        uint8_t decaps_original[RLWE_KEY_LEN] = {0};
        uint8_t decaps_tampered[RLWE_KEY_LEN] = {0};
        uint8_t expected_original[RLWE_KEY_LEN] = {0};
        uint8_t expected_tampered[RLWE_KEY_LEN] = {0};
        uint8_t expected_fallback[RLWE_KEY_LEN] = {0};
        uint8_t reencrypted[RLWE_CPA_CT_LEN] = {0};
        uint8_t message[RLWE_MSG_LEN] = {0};
        uint8_t tampered_message[RLWE_MSG_LEN] = {0};
        uint8_t message_domain[RLWE_MSG_LEN + 1 + RLWE_SEED_LEN] = {0};
        uint8_t kr[2 * RLWE_SEED_LEN] = {0};

        CCAKEM_KeyGen(sk, pk);
        CCAKEM_Encaps(ct, original_key, pk);
        const int rv_original = CCAKEM_Decaps(decaps_original, sk, ct);

        memcpy(ct_tampered, ct, sizeof(ct));
        const uint8_t padding_before = ct_tampered[1046];
        ct_tampered[1046] ^= 0x01;
        const int rv_tampered = CCAKEM_Decaps(decaps_tampered, sk, ct_tampered);

        const int cpa_rv_original = CPAPKE_Decrypt(message, sk, ct);
        const int cpa_rv_tampered = CPAPKE_Decrypt(tampered_message, sk, ct_tampered);

        derive_kr(kr, message_domain, message, pk);
        CPAPKE_Encrypt(reencrypted, pk, message, kr + RLWE_SEED_LEN);
        derive_explicit_key(expected_original, ct, kr + RLWE_SEED_LEN);
        derive_explicit_key(expected_tampered, ct_tampered, kr + RLWE_SEED_LEN);
        derive_explicit_key(
            expected_fallback,
            ct_tampered,
            sk + RLWE_CPA_SK_LEN + RLWE_CPA_PK_LEN);

        printf(
            "{\"trial\":%d,"
            "\"rlen\":1047,\"last_index\":1046,"
            "\"padding_before\":%u,\"padding_after\":%u,"
            "\"cmp_full\":%d,"
            "\"cpa_rv_original\":%d,\"cpa_rv_tampered\":%d,"
            "\"plaintext_equal\":%s,"
            "\"decaps_rv_original\":%d,\"decaps_rv_tampered\":%d,"
            "\"encaps_key_equals_decaps_original\":%s,"
            "\"decaps_tampered_differs\":%s,"
            "\"tampered_equals_success_kdf\":%s,"
            "\"tampered_equals_fallback_kdf\":%s,"
            "\"original_equals_success_kdf\":%s,"
            "\"reencrypted_equals_original\":%s}\n",
            trial,
            (unsigned)padding_before,
            (unsigned)ct_tampered[1046],
            cmp(ct, ct_tampered, RLWE_CCA_CT_LEN),
            cpa_rv_original,
            cpa_rv_tampered,
            different(message, tampered_message, RLWE_MSG_LEN) ? "false" : "true",
            rv_original,
            rv_tampered,
            different(original_key, decaps_original, RLWE_KEY_LEN) ? "false" : "true",
            different(decaps_original, decaps_tampered, RLWE_KEY_LEN) ? "true" : "false",
            different(decaps_tampered, expected_tampered, RLWE_KEY_LEN) ? "false" : "true",
            different(decaps_tampered, expected_fallback, RLWE_KEY_LEN) ? "false" : "true",
            different(decaps_original, expected_original, RLWE_KEY_LEN) ? "false" : "true",
            different(reencrypted, ct, RLWE_CPA_CT_LEN) ? "false" : "true");
    }

    return 0;
}
