#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "KEM_AlgorithmInstance.h"
#include "drng.h"

static void print_hex(const char *label, const uint8_t *data, size_t len) {
    printf("%s=", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    putchar('\n');
}

static void run_case(const char *name,
                     const uint8_t *sk, size_t sk_len,
                     const uint8_t *ct, size_t ct_len,
                     const uint8_t *sender_key, size_t key_len,
                     size_t mutation_index, uint8_t mask) {
    uint8_t *mutated = malloc(ct_len);
    uint8_t key[128] = {0};
    unsigned long long out_len = 0;
    memcpy(mutated, ct, ct_len);
    if (mutation_index < ct_len) {
        mutated[mutation_index] ^= mask;
    }

    int ret = kem_dec((unsigned char *)sk, sk_len,
                      mutated, ct_len,
                      key, &out_len);
    printf("case=%s index=%zu mask=0x%02x return=%d out_len=%llu equal_sender=%d\n",
           name, mutation_index, mask, ret, out_len,
           out_len == key_len && memcmp(key, sender_key, key_len) == 0);
    print_hex("mutated_ct_sha_input", mutated, ct_len);
    print_hex("dec_key", key, out_len);
    free(mutated);
}

int main(void) {
    const uint8_t seed[64] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f
    };
    const unsigned long long pk_len = kem_get_pk_len_bytes();
    const unsigned long long sk_len = kem_get_sk_len_bytes();
    const unsigned long long ct_len = kem_get_ct_len_bytes();
    const unsigned long long key_len = kem_get_ss_len_bytes();
    uint8_t *pk = calloc(pk_len, 1);
    uint8_t *sk = calloc(sk_len, 1);
    uint8_t *ct = calloc(ct_len, 1);
    uint8_t sender_key[128] = {0};
    uint8_t dec_key[128] = {0};
    unsigned long long out_pk = 0, out_sk = 0, out_ss = 0, out_ct = 0;

    init_random_number(&drng_algorithm, seed, sizeof(seed));
    int ret_keygen = kem_keygen(pk, &out_pk, sk, &out_sk);
    int ret_enc = kem_enc(pk, out_pk, sender_key, &out_ss, ct, &out_ct);
    int ret_dec = kem_dec(sk, out_sk, ct, out_ct, dec_key, &out_ss);

    printf("compiler_context=%s\n", __VERSION__);
    printf("lengths pk=%llu sk=%llu ct=%llu key=%llu\n",
           out_pk, out_sk, out_ct, key_len);
    printf("keygen_return=%d enc_return=%d dec_return=%d honest_equal=%d\n",
           ret_keygen, ret_enc, ret_dec,
           memcmp(sender_key, dec_key, key_len) == 0);
    print_hex("ct", ct, out_ct);
    print_hex("sender_key", sender_key, key_len);
    print_hex("honest_dec_key", dec_key, key_len);

    run_case("honest", sk, out_sk, ct, out_ct, sender_key, key_len, 0, 0x00);
    run_case("unused_lsb", sk, out_sk, ct, out_ct, sender_key, key_len,
             out_ct - 1, 0x01);
    run_case("last_byte_msb", sk, out_sk, ct, out_ct, sender_key, key_len,
             out_ct - 1, 0x80);
    run_case("checked_first_byte_lsb", sk, out_sk, ct, out_ct, sender_key,
             key_len, 0, 0x01);
    run_case("checked_first_byte_msb", sk, out_sk, ct, out_ct, sender_key,
             key_len, 0, 0x80);

    free(ct);
    free(sk);
    free(pk);
    return 0;
}
