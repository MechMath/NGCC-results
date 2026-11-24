#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "ccakem.h"
#include "auxfunc.h"

static int same(const uint8_t *a, const uint8_t *b, size_t n) {
    return memcmp(a, b, n) == 0;
}

static void rejection_key(uint8_t out[RLWE_KEY_LEN],
                          const uint8_t ct[RLWE_CCA_CT_LEN],
                          const uint8_t sk[RLWE_CCA_SK_LEN]) {
    uint8_t state[RLWE_CCA_CT_LEN + RLWE_SEED_LEN];
    memcpy(state, ct, RLWE_CCA_CT_LEN);
    memcpy(state + RLWE_CCA_CT_LEN,
           sk + RLWE_CPA_SK_LEN + RLWE_CPA_PK_LEN, RLWE_SEED_LEN);
    pseudoXOF(RLWE_KEY_LEN << 3, state,
              (RLWE_CCA_CT_LEN + RLWE_SEED_LEN) << 3, out);
}

int main(void) {
    static uint8_t sk[RLWE_CCA_SK_LEN];
    static uint8_t pk[RLWE_CCA_PK_LEN];
    static uint8_t ct[RLWE_CCA_CT_LEN];
    static uint8_t ct_omitted[RLWE_CCA_CT_LEN];
    static uint8_t ct_compared[RLWE_CCA_CT_LEN];
    static uint8_t enc_key[RLWE_KEY_LEN];
    static uint8_t key0[RLWE_KEY_LEN];
    static uint8_t key1[RLWE_KEY_LEN];
    static uint8_t key2[RLWE_KEY_LEN];
    static uint8_t ct_padding[RLWE_CCA_CT_LEN];
    static uint8_t key_padding[RLWE_KEY_LEN];
    static uint8_t reject1[RLWE_KEY_LEN];
    static uint8_t reject2[RLWE_KEY_LEN];
    static uint8_t reject_padding[RLWE_KEY_LEN];

    CCAKEM_Init();
    CCAKEM_KeyGen(sk, pk);
    CCAKEM_Encaps(ct, enc_key, pk);

    memcpy(ct_omitted, ct, sizeof(ct));
    ct_omitted[1] ^= 0x01;
    memcpy(ct_compared, ct, sizeof(ct));
    ct_compared[0] ^= 0x01;
    memcpy(ct_padding, ct, sizeof(ct));
    ct_padding[RLWE_CCA_CT_LEN - 1] ^= 0x01;

    int rc0 = CCAKEM_Decaps(key0, sk, ct);
    int rc1 = CCAKEM_Decaps(key1, sk, ct_omitted);
    int rc2 = CCAKEM_Decaps(key2, sk, ct_compared);
    int rc3 = CCAKEM_Decaps(key_padding, sk, ct_padding);
    rejection_key(reject1, ct_omitted, sk);
    rejection_key(reject2, ct_compared, sk);
    rejection_key(reject_padding, ct_padding, sk);

    printf("profile=Amoeba-576 ct_len=%d compared_bytes=%d\n",
           RLWE_CCA_CT_LEN, (RLWE_CCA_CT_LEN + 3) / 4);
    printf("unchanged rc=%d enc_key_eq=%d\n", rc0, same(enc_key, key0, sizeof(key0)));
    printf("omitted_index_1 rc=%d rejection_key_eq=%d key_eq_unchanged=%d\n",
           rc1, same(reject1, key1, sizeof(key1)), same(key0, key1, sizeof(key0)));
    printf("compared_index_0 rc=%d rejection_key_eq=%d key_eq_unchanged=%d\n",
           rc2, same(reject2, key2, sizeof(key2)), same(key0, key2, sizeof(key0)));
    printf("final_padding_bit rc=%d rejection_key_eq=%d key_eq_unchanged=%d\n",
           rc3, same(reject_padding, key_padding, sizeof(key_padding)),
           same(key0, key_padding, sizeof(key0)));

#ifdef SCAN_ALL_SINGLE_BITS
    int omitted_total = 0, omitted_accept = 0;
    int compared_total = 0, compared_accept = 0;
    static uint8_t test_ct[RLWE_CCA_CT_LEN];
    static uint8_t test_key[RLWE_KEY_LEN];
    static uint8_t expected_reject[RLWE_KEY_LEN];
    for (int i = 0; i < RLWE_CCA_CT_LEN; ++i) {
        memcpy(test_ct, ct, sizeof(test_ct));
        test_ct[i] ^= 0x01;
        int rc = CCAKEM_Decaps(test_key, sk, test_ct);
        rejection_key(expected_reject, test_ct, sk);
        int accepted_branch = (rc == 0) &&
                              !same(expected_reject, test_key, sizeof(test_key));
        if ((i & 3) != 0) {
            ++omitted_total;
            omitted_accept += accepted_branch;
        } else {
            ++compared_total;
            compared_accept += accepted_branch;
        }
    }
    printf("single_bit_flip_scan omitted_accept=%d/%d compared_accept=%d/%d\n",
           omitted_accept, omitted_total, compared_accept, compared_total);
#endif
    return 0;
}
