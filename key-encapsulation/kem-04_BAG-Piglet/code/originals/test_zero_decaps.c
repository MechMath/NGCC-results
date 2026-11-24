#include <stdio.h>
#include <string.h>

#include "ccakem.h"
#include "ffi_field.h"

int main(void) {
  uint8_t pk[CCAKEM_PK_SIZE];
  uint8_t sk[CCAKEM_SK_SIZE];
  uint8_t ct[CCAKEM_CT_SIZE] = {0};
  uint8_t key[CCAKEM_KEY_SIZE];

  ffi_field_init();
  ccakem_keygen(pk, sk, NULL);
  puts("keygen ok");
  fflush(stdout);
  ccakem_decaps(key, sk, ct);
  puts("zero-ciphertext decaps returned");
  for (size_t i = 0; i < sizeof(key); ++i) {
    printf("%02X", key[i]);
  }
  putchar('\n');
  return 0;
}
