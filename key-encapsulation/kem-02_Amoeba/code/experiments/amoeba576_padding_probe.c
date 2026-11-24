#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "auxfunc.h"
#include "ccakem.h"
#include "drng.h"
#include "KEM_AlgorithmInstance.h"
#include "params.h"

extern DRNG_ctx drng_algorithm;

static int same_bytes(const uint8_t *a, const uint8_t *b, size_t len)
{
    for (size_t i = 0; i < len; ++i) {
        if (a[i] != b[i]) {
            return 0;
        }
    }
    return 1;
}

static size_t first_diff(const uint8_t *a, const uint8_t *b, size_t len)
{
    size_t i;
    for (i = 0; i < len; ++i) {
        if (a[i] != b[i]) {
            return i;
        }
    }
    return len;
}

static void rejection_key(uint8_t key[RLWE_KEY_LEN],
                          const uint8_t ct[RLWE_CCA_CT_LEN],
                          const uint8_t sk[RLWE_CCA_SK_LEN])
{
    uint8_t state[RLWE_CCA_CT_LEN + RLWE_SEED_LEN] = {0};
    memcpy(state, ct, RLWE_CCA_CT_LEN);
    memcpy(state + RLWE_CCA_CT_LEN,
           sk + RLWE_CPA_SK_LEN + RLWE_CPA_PK_LEN,
           RLWE_SEED_LEN);
    if (pseudoXOF(RLWE_KEY_LEN << 3,
                  state,
                  (RLWE_CCA_CT_LEN + RLWE_SEED_LEN) << 3,
                  key) != 0) {
        fprintf(stderr, "pseudoXOF failed while deriving rejection key\n");
        exit(2);
    }
}

static void write_bin(const char *path, const uint8_t *data, size_t len)
{
    FILE *f = fopen(path, "wb");
    if (f == NULL) {
        fprintf(stderr, "cannot open %s: %s\n", path, strerror(errno));
        exit(2);
    }
    if (fwrite(data, 1, len, f) != len) {
        fprintf(stderr, "short write to %s\n", path);
        fclose(f);
        exit(2);
    }
    if (fclose(f) != 0) {
        fprintf(stderr, "cannot close %s: %s\n", path, strerror(errno));
        exit(2);
    }
}

int main(int argc, char **argv)
{
    const char *outdir = argc > 1 ? argv[1] : "experiments/amoeba576-probe";
    char path[1024];
    uint8_t seed[RLWE_SEED_LEN];
    uint8_t sk[RLWE_CCA_SK_LEN] = {0};
    uint8_t pk[RLWE_CCA_PK_LEN] = {0};
    uint8_t ct[RLWE_CCA_CT_LEN] = {0};
    uint8_t ct_padding[RLWE_CCA_CT_LEN] = {0};
    uint8_t ct_checked[RLWE_CCA_CT_LEN] = {0};
    uint8_t sender_key[RLWE_KEY_LEN] = {0};
    uint8_t control_key[RLWE_KEY_LEN] = {0};
    uint8_t padding_key[RLWE_KEY_LEN] = {0};
    uint8_t checked_key[RLWE_KEY_LEN] = {0};
    uint8_t padding_reject_key[RLWE_KEY_LEN] = {0};
    uint8_t checked_reject_key[RLWE_KEY_LEN] = {0};
    uint8_t api_sk[RLWE_CCA_SK_LEN] = {0};
    uint8_t api_pk[RLWE_CCA_PK_LEN] = {0};
    uint8_t api_ct[RLWE_CCA_CT_LEN] = {0};
    uint8_t api_ct_padding[RLWE_CCA_CT_LEN] = {0};
    uint8_t api_sender_key[RLWE_KEY_LEN] = {0};
    uint8_t api_control_key[RLWE_KEY_LEN] = {0};
    uint8_t api_padding_key[RLWE_KEY_LEN] = {0};
    unsigned long long api_pk_len = 0;
    unsigned long long api_sk_len = 0;
    unsigned long long api_ct_len = 0;
    unsigned long long api_sender_key_len = 0;
    unsigned long long api_control_key_len = 0;
    unsigned long long api_padding_key_len = 0;

    for (size_t i = 0; i < sizeof(seed); ++i) {
        seed[i] = (uint8_t)(0x40u + (uint8_t)i);
    }
    if (init_random_number(&drng_algorithm, seed, sizeof(seed)) != 0) {
        fprintf(stderr, "DRNG initialization failed\n");
        return 2;
    }

    CCAKEM_KeyGen(sk, pk);
    CCAKEM_Encaps(ct, sender_key, pk);

    memcpy(ct_padding, ct, sizeof(ct));
    ct_padding[RLWE_CCA_CT_LEN - 1] ^= 0x01u;
    memcpy(ct_checked, ct, sizeof(ct));
    ct_checked[0] ^= 0x01u;

    int control_rc = CCAKEM_Decaps(control_key, sk, ct);
    int padding_rc = CCAKEM_Decaps(padding_key, sk, ct_padding);
    int checked_rc = CCAKEM_Decaps(checked_key, sk, ct_checked);

    rejection_key(padding_reject_key, ct_padding, sk);
    rejection_key(checked_reject_key, ct_checked, sk);

    int api_keygen_rc = kem_keygen(api_pk, &api_pk_len, api_sk, &api_sk_len);
    int api_enc_rc = kem_enc(api_pk, api_pk_len, api_sender_key,
                             &api_sender_key_len, api_ct, &api_ct_len);
    memcpy(api_ct_padding, api_ct, sizeof(api_ct_padding));
    api_ct_padding[api_ct_len - 1] ^= 0x01u;
    int api_control_rc = kem_dec(api_sk, api_sk_len, api_ct, api_ct_len,
                                 api_control_key, &api_control_key_len);
    int api_padding_rc = kem_dec(api_sk, api_sk_len, api_ct_padding, api_ct_len,
                                 api_padding_key, &api_padding_key_len);

    printf("profile=Amoeba-%d\n", SECURITY_LEVEL);
    printf("pk_len=%d\n", RLWE_CCA_PK_LEN);
    printf("sk_len=%d\n", RLWE_CCA_SK_LEN);
    printf("ct_len=%d\n", RLWE_CCA_CT_LEN);
    printf("cpa_ct_len=%d\n", RLWE_CPA_CT_LEN);
    printf("c2_significant_bits=%d\n", RLWE_D2 * RLWE_ECC_N);
    printf("c2_padding_bits=%d\n",
           (BIT_TO_BYTE(RLWE_D2 * RLWE_ECC_N) * 8) -
               (RLWE_D2 * RLWE_ECC_N));
    printf("modified_ct_index=%d\n", RLWE_CCA_CT_LEN - 1);
    printf("modified_ct_index_mod4=%d\n", (RLWE_CCA_CT_LEN - 1) % 4);
    printf("ct_original_last_byte=%02x\n", ct[RLWE_CCA_CT_LEN - 1]);
    printf("ct_padding_last_byte=%02x\n",
           ct_padding[RLWE_CCA_CT_LEN - 1]);

    printf("control_rc=%d control_equal_sender=%d\n",
           control_rc, same_bytes(control_key, sender_key, RLWE_KEY_LEN));
    printf("padding_rc=%d padding_equal_sender=%d padding_equal_rejection=%d\n",
           padding_rc,
           same_bytes(padding_key, sender_key, RLWE_KEY_LEN),
           same_bytes(padding_key, padding_reject_key, RLWE_KEY_LEN));
    printf("checked_rc=%d checked_equal_sender=%d checked_equal_rejection=%d\n",
           checked_rc,
           same_bytes(checked_key, sender_key, RLWE_KEY_LEN),
           same_bytes(checked_key, checked_reject_key, RLWE_KEY_LEN));
    printf("api_keygen_rc=%d api_pk_len=%llu api_sk_len=%llu\n",
           api_keygen_rc, api_pk_len, api_sk_len);
    printf("api_enc_rc=%d api_ct_len=%llu api_sender_key_len=%llu\n",
           api_enc_rc, api_ct_len, api_sender_key_len);
    printf("api_ct_len_equals_expected=%d\n",
           api_ct_len == (unsigned long long)RLWE_CCA_CT_LEN);
    printf("api_control_rc=%d api_control_key_len=%llu "
           "api_control_equal_sender=%d\n",
           api_control_rc, api_control_key_len,
           same_bytes(api_control_key, api_sender_key, RLWE_KEY_LEN));
    printf("api_padding_rc=%d api_padding_key_len=%llu "
           "api_padding_equal_sender=%d\n",
           api_padding_rc, api_padding_key_len,
           same_bytes(api_padding_key, api_sender_key, RLWE_KEY_LEN));
    printf("padding_diff_index=%zu\n",
           first_diff(padding_key, sender_key, RLWE_KEY_LEN));
    printf("checked_diff_index=%zu\n",
           first_diff(checked_key, sender_key, RLWE_KEY_LEN));

    snprintf(path, sizeof(path), "%s/sk.bin", outdir);
    write_bin(path, sk, sizeof(sk));
    snprintf(path, sizeof(path), "%s/pk.bin", outdir);
    write_bin(path, pk, sizeof(pk));
    snprintf(path, sizeof(path), "%s/ct.bin", outdir);
    write_bin(path, ct, sizeof(ct));
    snprintf(path, sizeof(path), "%s/ct_padding_mutated.bin", outdir);
    write_bin(path, ct_padding, sizeof(ct_padding));
    snprintf(path, sizeof(path), "%s/ct_checked_mutated.bin", outdir);
    write_bin(path, ct_checked, sizeof(ct_checked));
    snprintf(path, sizeof(path), "%s/sender_key.bin", outdir);
    write_bin(path, sender_key, sizeof(sender_key));
    snprintf(path, sizeof(path), "%s/control_key.bin", outdir);
    write_bin(path, control_key, sizeof(control_key));
    snprintf(path, sizeof(path), "%s/padding_key.bin", outdir);
    write_bin(path, padding_key, sizeof(padding_key));
    snprintf(path, sizeof(path), "%s/checked_key.bin", outdir);
    write_bin(path, checked_key, sizeof(checked_key));
    snprintf(path, sizeof(path), "%s/padding_rejection_key.bin", outdir);
    write_bin(path, padding_reject_key, sizeof(padding_reject_key));
    snprintf(path, sizeof(path), "%s/checked_rejection_key.bin", outdir);
    write_bin(path, checked_reject_key, sizeof(checked_reject_key));
    snprintf(path, sizeof(path), "%s/api_ct.bin", outdir);
    write_bin(path, api_ct, sizeof(api_ct));
    snprintf(path, sizeof(path), "%s/api_ct_padding_mutated.bin", outdir);
    write_bin(path, api_ct_padding, sizeof(api_ct_padding));
    snprintf(path, sizeof(path), "%s/api_sender_key.bin", outdir);
    write_bin(path, api_sender_key, sizeof(api_sender_key));
    snprintf(path, sizeof(path), "%s/api_control_key.bin", outdir);
    write_bin(path, api_control_key, sizeof(api_control_key));
    snprintf(path, sizeof(path), "%s/api_padding_key.bin", outdir);
    write_bin(path, api_padding_key, sizeof(api_padding_key));

    return 0;
}
