#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "auxfunc.h"
#include "bag_piglet.h"
#include "ccakem.h"
#include "drng.h"
#include "ffi_field.h"
#include "parameters.h"

DRNG_ctx drng_algorithm;

static void derive_pke_seed(uint8_t pke_seed[SEEDEXPANDER_SEED_BYTES],
                            const uint8_t master_seed[CCAKEM_SK_SIZE]) {
  uint8_t input[CCAKEM_SK_SIZE + 1];
  uint8_t expanded[SEEDEXPANDER_SEED_BYTES + PARAMS_PREKEY_SIZE];

  memcpy(input, master_seed, CCAKEM_SK_SIZE);
  input[CCAKEM_SK_SIZE] = 0x01;
  pseudoXOF(8ULL * sizeof(expanded), input, 8ULL * sizeof(input), expanded);
  memcpy(pke_seed, expanded, SEEDEXPANDER_SEED_BYTES);
}

static void print_hex(const char *label, const uint8_t *value, size_t len) {
  printf("%s=", label);
  for(size_t i = 0; i < len; ++i) {
    printf("%02x", (unsigned int) value[i]);
  }
  putchar('\n');
}

int main(void) {
  uint8_t pk[CCAKEM_PK_SIZE];
  uint8_t sk[CCAKEM_SK_SIZE];
  uint8_t ct[CCAKEM_CT_SIZE];
  uint8_t ct_padding[CCAKEM_CT_SIZE];
  uint8_t ct_padding2[CCAKEM_CT_SIZE];
  uint8_t ct_used_bit[CCAKEM_CT_SIZE];
  uint8_t ct_salt[CCAKEM_CT_SIZE];
  uint8_t key_encaps[CCAKEM_KEY_SIZE];
  uint8_t key_valid[CCAKEM_KEY_SIZE];
  uint8_t key_padding[CCAKEM_KEY_SIZE];
  uint8_t key_padding2[CCAKEM_KEY_SIZE];
  uint8_t key_used_bit[CCAKEM_KEY_SIZE];
  uint8_t key_salt[CCAKEM_KEY_SIZE];
  uint8_t seed[CCAKEM_SK_SIZE];
  uint8_t drng_seed[64];
  uint8_t pke_seed[SEEDEXPANDER_SEED_BYTES];
  uint8_t pke_pk[CPAPKE_PK_SIZE];
  uint8_t pke_sk[CPAPKE_SK_SIZE];
  uint8_t message[CPAPKE_PT_SIZE];
  uint8_t message_padding[CPAPKE_PT_SIZE];
  uint8_t message_padding2[CPAPKE_PT_SIZE];
  uint8_t message_used_bit[CPAPKE_PT_SIZE];

  for(size_t i = 0; i < sizeof(seed); ++i) {
    seed[i] = (uint8_t) i;
  }
  for(size_t i = 0; i < sizeof(drng_seed); ++i) {
    drng_seed[i] = (uint8_t) (0xa5U ^ (uint8_t) i);
  }

  init_random_number(&drng_algorithm, drng_seed, sizeof(drng_seed));
  ffi_field_init();
  ccakem_keygen(pk, sk, seed);
  derive_pke_seed(pke_seed, sk);
  bag_piglet_pke_keygen(pke_pk, pke_sk, pke_seed);
  ccakem_encaps(key_encaps, ct, pk, NULL);
  ccakem_decaps(key_valid, sk, ct);
  bag_piglet_pke_decrypt(message, ct, pke_sk);

  memcpy(ct_padding, ct, sizeof(ct));
  ct_padding[CPAPKE_CT_SIZE - 1] ^= 0x80;

  memcpy(ct_padding2, ct, sizeof(ct));
  ct_padding2[CPAPKE_CT_SIZE - 1] ^= 0x10;

  memcpy(ct_used_bit, ct, sizeof(ct));
  ct_used_bit[CPAPKE_CT_SIZE - 1] ^= 0x01;

  memcpy(ct_salt, ct, sizeof(ct));
  ct_salt[CPAPKE_CT_SIZE] ^= 0x01;

  ccakem_decaps(key_padding, sk, ct_padding);
  ccakem_decaps(key_padding2, sk, ct_padding2);
  ccakem_decaps(key_used_bit, sk, ct_used_bit);
  ccakem_decaps(key_salt, sk, ct_salt);
  bag_piglet_pke_decrypt(message_padding, ct_padding, pke_sk);
  bag_piglet_pke_decrypt(message_padding2, ct_padding2, pke_sk);
  bag_piglet_pke_decrypt(message_used_bit, ct_used_bit, pke_sk);

  printf("PK_LEN=%d\n", CCAKEM_PK_SIZE);
  printf("SK_LEN=%d\n", CCAKEM_SK_SIZE);
  printf("PKE_CT_LEN=%d\n", CPAPKE_CT_SIZE);
  printf("KEM_CT_LEN=%d\n", CCAKEM_CT_SIZE);
  printf("SS_LEN=%d\n", CCAKEM_KEY_SIZE);
  printf("padding_mutation_changes_wire=%d\n",
         memcmp(ct, ct_padding, sizeof(ct)) != 0);
  printf("padding_variants_differ=%d\n",
         memcmp(ct_padding, ct_padding2, sizeof(ct)) != 0);
  printf("used_bit_mutation_changes_wire=%d\n",
         memcmp(ct, ct_used_bit, sizeof(ct)) != 0);
  printf("salt_mutation_changes_wire=%d\n",
         memcmp(ct, ct_salt, sizeof(ct)) != 0);
  printf("positive_control_encaps_eq_decaps=%d\n",
         memcmp(key_encaps, key_valid, sizeof(key_valid)) == 0);
  printf("padding_invalid_key_eq_original=%d\n",
         memcmp(key_valid, key_padding, sizeof(key_valid)) == 0);
  printf("used_bit_invalid_key_eq_original=%d\n",
         memcmp(key_valid, key_used_bit, sizeof(key_valid)) == 0);
  printf("salt_invalid_key_eq_original=%d\n",
         memcmp(key_valid, key_salt, sizeof(key_valid)) == 0);
  printf("padding_invalid_key_eq_used_bit_invalid=%d\n",
         memcmp(key_padding, key_used_bit, sizeof(key_valid)) == 0);
  printf("two_padding_invalid_keys_equal=%d\n",
         memcmp(key_padding, key_padding2, sizeof(key_valid)) == 0);
  printf("padding1_decodes_original_message=%d\n",
         memcmp(message, message_padding, sizeof(message)) == 0);
  printf("padding2_decodes_original_message=%d\n",
         memcmp(message, message_padding2, sizeof(message)) == 0);
  printf("used_bit_decodes_original_message=%d\n",
         memcmp(message, message_used_bit, sizeof(message)) == 0);
  print_hex("K_valid", key_valid, sizeof(key_valid));
  print_hex("K_padding", key_padding, sizeof(key_padding));
  print_hex("K_padding2", key_padding2, sizeof(key_padding2));
  print_hex("K_used_bit", key_used_bit, sizeof(key_used_bit));
  print_hex("K_salt", key_salt, sizeof(key_salt));
  print_hex("M_original", message, sizeof(message));
  print_hex("M_padding", message_padding, sizeof(message_padding));
  print_hex("M_used_bit", message_used_bit, sizeof(message_used_bit));

  return 0;
}
