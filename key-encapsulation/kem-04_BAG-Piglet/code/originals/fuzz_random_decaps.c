#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ccakem.h"
#include "ffi_field.h"

static uint64_t state = UINT64_C(0x9e3779b97f4a7c15);

static uint8_t next_byte(void) {
  state ^= state << 13;
  state ^= state >> 7;
  state ^= state << 17;
  return (uint8_t)(state >> 32);
}

int main(int argc, char **argv) {
  const int trials = argc > 1 ? atoi(argv[1]) : 1000;
  uint8_t pk[CCAKEM_PK_SIZE];
  uint8_t sk[CCAKEM_SK_SIZE];
  uint8_t ct[CCAKEM_CT_SIZE];
  uint8_t key[CCAKEM_KEY_SIZE];

  ffi_field_init();
  ccakem_keygen(pk, sk, NULL);
  for (int n = 0; n < trials; ++n) {
    for (size_t i = 0; i < sizeof(ct); ++i) {
      ct[i] = next_byte();
    }
    ccakem_decaps(key, sk, ct);
  }
  printf("variant=%u trials=%d result=returned\n",
         (unsigned)PARAM_SECURITY, trials);
  return 0;
}
