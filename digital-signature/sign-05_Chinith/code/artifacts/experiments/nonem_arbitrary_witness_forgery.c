#include "sm4th_d3_128f_loose.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
  uint8_t sk_key[16] = {
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
      0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
  };
  uint8_t sk_input[16] = {
      0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
      0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
  };
  uint8_t pk[32] = {0};
  uint8_t sk[32] = {0};
  uint8_t rho[16] = {0};
  const uint8_t msg[] = "forged non-EM message";
  const size_t sig_len = sm4th_d3_128f_loose_signature_size();
  uint8_t *sig = calloc(1, sig_len);
  if (!sig) {
    return 2;
  }
  if (sm4th_d3_128f_loose_keygen(pk, sk, sk_key, sk_input) != 0) {
    return 3;
  }

  sm4th_d3_128f_loose_unpacked_private_key_t forged;
  memset(&forged, 0, sizeof(forged));
  memcpy(forged.owf_input, pk, 16);
  memcpy(forged.owf_output, pk + 16, 16);
  forged.witness = calloc(1, 226); /* params->ell / 8; deliberately invalid */
  if (!forged.witness) {
    return 4;
  }
  size_t out_len = sig_len;
  int sign_rc = sm4th_d3_128f_loose_unpacked_sign_with_randomness(
      &forged, msg, sizeof(msg) - 1, rho, sizeof(rho), sig, &out_len);
  int verify_rc = sm4th_d3_128f_loose_verify(
      pk, msg, sizeof(msg) - 1, sig, out_len);
  printf("sign_rc=%d\nverify_rc=%d\nsignature_len=%zu\npk=",
         sign_rc, verify_rc, out_len);
  for (size_t i = 0; i < sizeof(pk); ++i) {
    printf("%02x", pk[i]);
  }
  putchar('\n');

  free(forged.witness);
  free(sig);
  return verify_rc == 0 ? 0 : 1;
}
