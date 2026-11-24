#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "auxfunc.h"
#include "cpapke.h"

void ID(uint8_t id[RLWE_SEED_LEN], const uint8_t pk[RLWE_CCA_PK_LEN]);
void CCAKEM_KeyGen(uint8_t sk[RLWE_CCA_SK_LEN],
                   uint8_t pk[RLWE_CCA_PK_LEN]);
void CCAKEM_Encaps(uint8_t ct[RLWE_CCA_CT_LEN],
                   uint8_t key[RLWE_KEY_LEN],
                   const uint8_t pk[RLWE_CCA_PK_LEN]);
int CCAKEM_Decaps(uint8_t key[RLWE_KEY_LEN],
                  const uint8_t sk[RLWE_CCA_SK_LEN],
                  const uint8_t ct[RLWE_CCA_CT_LEN]);

static int same_bytes(const uint8_t *a, const uint8_t *b, size_t n) {
    return memcmp(a, b, n) == 0;
}

int main(void) {
    uint8_t sk[RLWE_CCA_SK_LEN] = {0};
    uint8_t pk[RLWE_CCA_PK_LEN] = {0};
    uint8_t ct[RLWE_CCA_CT_LEN] = {0};
    uint8_t ct_mut[RLWE_CCA_CT_LEN] = {0};
    uint8_t key_good[RLWE_KEY_LEN] = {0};
    uint8_t key_mut[RLWE_KEY_LEN] = {0};
    uint8_t key_expected_accept[RLWE_KEY_LEN] = {0};
    uint8_t key_expected_reject[RLWE_KEY_LEN] = {0};
    uint8_t m[RLWE_MSG_LEN + 1 + RLWE_SEED_LEN] = {0};
    uint8_t Kr[RLWE_SEED_LEN * 2] = {0};
    uint8_t ct2[RLWE_CPA_CT_LEN] = {0};
    uint8_t state[RLWE_CCA_CT_LEN + RLWE_SEED_LEN] = {0};

    CPAPKE_Init();
    CCAKEM_KeyGen(sk, pk);
    CCAKEM_Encaps(ct, key_good, pk);

    memcpy(ct_mut, ct, sizeof(ct));
    ct_mut[RLWE_CCA_CT_LEN - 1] ^= 0x01;
    int decap_rc = CCAKEM_Decaps(key_mut, sk, ct_mut);

    if (CPAPKE_Decrypt(m, sk, ct_mut) != 0) {
        puts("CPAPKE_Decrypt failed");
        return 2;
    }
    ID(m + RLWE_MSG_LEN + 1, sk + RLWE_CPA_SK_LEN);
    for (size_t off = 0; off < RLWE_SEED_LEN * 2; off += 32) {
        sm3hash(256, m, (RLWE_MSG_LEN + 1 + RLWE_SEED_LEN) << 3, Kr + off);
        m[RLWE_MSG_LEN]++;
    }

    CPAPKE_Encrypt(ct2, sk + RLWE_CPA_SK_LEN, m, Kr + RLWE_SEED_LEN);
    int canonical_difference_count = 0;
    for (size_t i = 0; i < RLWE_CPA_CT_LEN; i++) {
        canonical_difference_count += (ct2[i] != ct_mut[i]);
    }
    int comparator_stride_difference_count = 0;
    for (size_t i = 0; i < (size_t)RLWE_CPA_CT_LEN; i += 4) {
        comparator_stride_difference_count += (ct2[i] != ct_mut[i]);
    }

    memcpy(state, ct_mut, RLWE_CCA_CT_LEN);
    memcpy(state + RLWE_CCA_CT_LEN, Kr, RLWE_SEED_LEN);
    pseudoXOF(RLWE_KEY_LEN << 3, state,
              (RLWE_CCA_CT_LEN + RLWE_SEED_LEN) << 3,
              key_expected_accept);

    memcpy(state, ct_mut, RLWE_CCA_CT_LEN);
    memcpy(state + RLWE_CCA_CT_LEN,
           sk + RLWE_CPA_SK_LEN + RLWE_CPA_PK_LEN, RLWE_SEED_LEN);
    pseudoXOF(RLWE_KEY_LEN << 3, state,
              (RLWE_CCA_CT_LEN + RLWE_SEED_LEN) << 3,
              key_expected_reject);

    printf("profile=%d ct_len=%d final_index=%d final_index_mod4=%d\n",
           SECURITY_LEVEL, RLWE_CCA_CT_LEN, RLWE_CCA_CT_LEN - 1,
           (RLWE_CCA_CT_LEN - 1) % 4);
    printf("d2=%d ell=%d significant_c2_bits=%d c2_bytes=%d "
           "c2_unused_low_bits=%d c1_bytes=%d\n",
           RLWE_D2, RLWE_ECC_N, RLWE_D2 * RLWE_ECC_N,
           BIT_TO_BYTE(RLWE_D2 * RLWE_ECC_N),
           BIT_TO_BYTE(RLWE_D2 * RLWE_ECC_N) * 8 - RLWE_D2 * RLWE_ECC_N,
           BIT_TO_BYTE(RLWE_D1 * RLWE_K * RLWE_N));
    printf("decap_rc=%d\n", decap_rc);
    printf("canonical_difference_count=%d\n", canonical_difference_count);
    printf("comparator_stride_difference_count=%d\n",
           comparator_stride_difference_count);
    printf("mutated_key_matches_forced_accept=%d\n",
           same_bytes(key_mut, key_expected_accept, RLWE_KEY_LEN));
    printf("mutated_key_matches_reject=%d\n",
           same_bytes(key_mut, key_expected_reject, RLWE_KEY_LEN));
    printf("mutated_key_equals_original=%d\n",
           same_bytes(key_mut, key_good, RLWE_KEY_LEN));
    int padding_bits =
        BIT_TO_BYTE(RLWE_D2 * RLWE_ECC_N) * 8 - RLWE_D2 * RLWE_ECC_N;
    int accepted_variants = 0;
    int rejected_variants = 0;
    for (int mask = 1; mask < (1 << padding_bits); mask++) {
        uint8_t candidate[RLWE_CCA_CT_LEN];
        uint8_t candidate_key[RLWE_KEY_LEN] = {0};
        uint8_t candidate_accept[RLWE_KEY_LEN] = {0};
        uint8_t candidate_reject[RLWE_KEY_LEN] = {0};
        memcpy(candidate, ct, sizeof(candidate));
        candidate[RLWE_CCA_CT_LEN - 1] ^= (uint8_t)mask;
        if (CCAKEM_Decaps(candidate_key, sk, candidate) != 0) {
            puts("candidate decapsulation failed");
            return 3;
        }
        memcpy(state, candidate, RLWE_CCA_CT_LEN);
        memcpy(state + RLWE_CCA_CT_LEN, Kr, RLWE_SEED_LEN);
        pseudoXOF(RLWE_KEY_LEN << 3, state,
                  (RLWE_CCA_CT_LEN + RLWE_SEED_LEN) << 3,
                  candidate_accept);
        memcpy(state, candidate, RLWE_CCA_CT_LEN);
        memcpy(state + RLWE_CCA_CT_LEN,
               sk + RLWE_CPA_SK_LEN + RLWE_CPA_PK_LEN, RLWE_SEED_LEN);
        pseudoXOF(RLWE_KEY_LEN << 3, state,
                  (RLWE_CCA_CT_LEN + RLWE_SEED_LEN) << 3,
                  candidate_reject);
        if (same_bytes(candidate_key, candidate_accept, RLWE_KEY_LEN)) {
            accepted_variants++;
        } else if (same_bytes(candidate_key, candidate_reject, RLWE_KEY_LEN)) {
            rejected_variants++;
        } else {
            printf("unclassified_padding_variant=0x%x\n", mask);
            return 4;
        }
    }
    printf("nonzero_padding_variants=%d accepted_variants=%d "
           "rejected_variants=%d\n",
           1 << padding_bits, accepted_variants, rejected_variants);
    return 0;
}
