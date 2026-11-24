#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bag_piglet.h"
#include "ffi_field.h"
#include "ffi_vec.h"
#include "parameters.h"

static uint64_t state = UINT64_C(0x243f6a8885a308d3);

static uint8_t next_byte(void) {
  state ^= state << 13;
  state ^= state >> 7;
  state ^= state << 17;
  return (uint8_t)(state >> 32);
}

static void fill(uint8_t *out, size_t size) {
  for (size_t i = 0; i < size; ++i) {
    out[i] = next_byte();
  }
}

int main(int argc, char **argv) {
  const int trials = argc > 1 ? atoi(argv[1]) : 1000;
  uint8_t pk[CPAPKE_PK_SIZE];
  uint8_t sk[CPAPKE_SK_SIZE];
  uint8_t message[CPAPKE_PT_SIZE];
  uint8_t decoded[CPAPKE_PT_SIZE];
  uint8_t ciphertext[CPAPKE_CT_SIZE];
  uint8_t key_seed[PARAMS_SEED_SIZE];
  uint8_t enc_seed[PARAMS_SEED_SIZE];
  int failures = 0;

  ffi_field_init();
  fill(key_seed, sizeof(key_seed));
  bag_piglet_pke_keygen(pk, sk, key_seed);
  for (int n = 0; n < trials; ++n) {
    message_random2(message, PARAM_K);
    fill(enc_seed, sizeof(enc_seed));
    bag_piglet_pke_encrypt(message, ciphertext, pk, enc_seed);
    bag_piglet_pke_decrypt(decoded, ciphertext, sk);
    failures += memcmp(message, decoded, sizeof(message)) != 0;
  }
  printf("variant=%u trials=%d failures=%d\n",
         (unsigned)PARAM_SECURITY, trials, failures);
  return failures != 0;
}
