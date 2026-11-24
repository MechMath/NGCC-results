#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "auxfunc.h"
#include "cpapke.h"
#include "drng.h"
#include "params.h"

extern DRNG_ctx drng_algorithm;
extern int32_t cmp(uint8_t *c1, uint8_t *c2, int32_t len);
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

static int same(const uint8_t *a, const uint8_t *b, size_t length) {
    return memcmp(a, b, length) == 0;
}

static void print_hex(const uint8_t *data, size_t length) {
    for (size_t i = 0; i < length; ++i) {
        printf("%02x", data[i]);
    }
}

int main(void) {
    uint8_t seed[64];
    for (size_t i = 0; i < sizeof(seed); ++i) {
        seed[i] = (uint8_t)i;
    }
    if (init_random_number(&drng_algorithm, seed, sizeof(seed)) != 0) {
        return 2;
    }

    uint8_t sk[RLWE_CCA_SK_LEN] = {0};
    uint8_t pk[RLWE_CCA_PK_LEN] = {0};
    uint8_t ct[RLWE_CCA_CT_LEN] = {0};
    uint8_t ct2[RLWE_CCA_CT_LEN] = {0};
    uint8_t encaps_key[RLWE_KEY_LEN] = {0};
    uint8_t decaps_key[RLWE_KEY_LEN] = {0};
    uint8_t tampered_key[RLWE_KEY_LEN] = {0};
    uint8_t msg[RLWE_MSG_LEN] = {0};
    uint8_t tampered_msg[RLWE_MSG_LEN] = {0};

    CCAKEM_KeyGen(sk, pk);
    CCAKEM_Encaps(ct, encaps_key, pk);
    const int original_return = CCAKEM_Decaps(decaps_key, sk, ct);

    memcpy(ct2, ct, sizeof(ct));
    const unsigned before = ct2[1046];
    ct2[1046] ^= 0x01;
    const int tampered_return = CCAKEM_Decaps(tampered_key, sk, ct2);

    const int decrypt_return = CPAPKE_Decrypt(msg, sk, ct);
    const int tampered_decrypt_return = CPAPKE_Decrypt(tampered_msg, sk, ct2);

    printf("seed=");
    print_hex(seed, sizeof(seed));
    printf("\nct_original=");
    print_hex(ct, sizeof(ct));
    printf("\nct_tampered=");
    print_hex(ct2, sizeof(ct2));
    printf("\nencaps_key=");
    print_hex(encaps_key, sizeof(encaps_key));
    printf("\ndecaps_key=");
    print_hex(decaps_key, sizeof(decaps_key));
    printf("\ntampered_key=");
    print_hex(tampered_key, sizeof(tampered_key));
    printf("\n");
    printf("ct_length=%d last_index=1046 unused_mask=01 before=%u after=%u cmp_result=%d\n",
           RLWE_CCA_CT_LEN, before, ct2[1046], cmp(ct, ct2, RLWE_CCA_CT_LEN));
    printf("original_decaps_return=%d tampered_decaps_return=%d\n",
           original_return, tampered_return);
    printf("CPA_decrypt_returns=%d,%d plaintext_equal=%s\n",
           decrypt_return, tampered_decrypt_return,
           same(msg, tampered_msg, sizeof(msg)) ? "true" : "false");
    printf("encaps_equals_decaps=%s tampered_differs=%s\n",
           same(encaps_key, decaps_key, sizeof(encaps_key)) ? "true" : "false",
           same(decaps_key, tampered_key, sizeof(tampered_key)) ? "false" : "true");
    return 0;
}
