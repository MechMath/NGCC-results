#include "sm4th_d3_128f_loose.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const uint8_t target_pk[32] = {
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0xa7, 0x38, 0x51, 0xaa, 0x43, 0x41, 0xe9, 0x68,
    0xc7, 0x1d, 0xd8, 0xa3, 0xa0, 0xc8, 0x49, 0x7c,
};

int main(void) {
  static const uint8_t msg[] = "public-key-only non-EM forgery";
  const size_t sig_len = sm4th_d3_128f_loose_signature_size();
  uint8_t rho[16] = {0};
  uint8_t witness[226] = {0};
  uint8_t *sig = calloc(1, sig_len);
  if (!sig) {
    return 2;
  }

  sm4th_d3_128f_loose_unpacked_private_key_t attacker;
  memset(&attacker, 0, sizeof(attacker));
  memcpy(attacker.owf_input, target_pk, 16);
  memcpy(attacker.owf_output, target_pk + 16, 16);
  attacker.witness = witness;

  size_t out_len = sig_len;
  int sign_rc = sm4th_d3_128f_loose_unpacked_sign_with_randomness(
      &attacker, msg, sizeof(msg) - 1, rho, sizeof(rho), sig, &out_len);
  int verify_rc = sm4th_d3_128f_loose_verify(
      target_pk, msg, sizeof(msg) - 1, sig, out_len);
  printf("sign_rc=%d verify_rc=%d sig_len=%zu\n", sign_rc, verify_rc, out_len);

  free(sig);
  return sign_rc == 0 && verify_rc == 0 ? 0 : 1;
}
